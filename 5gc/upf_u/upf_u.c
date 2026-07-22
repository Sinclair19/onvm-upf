/*
# Copyright 2026 University of California, Riverside and National Yang Ming Chiao Tung University
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
*/

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <time.h>
#include <unistd.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_gtp.h>
#include <rte_ip.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_meter.h>
#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_ring.h>
#include <rte_ring_peek.h>
#include <rte_spinlock.h>
#include <rte_tcp.h>

#include "gtp.h"
#include "upf_context.h"
#include "utlt_debug.h"
#include "onvm_flow_table.h"
#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"
#include "list.h"

#include "upf_events.h"
#include "upf_cls_ctrl.h"
#include "upf_sess_buf.h"

#include "../classifiers/upf_cls_adapter.h"
#include "../classifiers/classifier_wrapper.h"

#include "upf_u_helper.h"
#include "upf_u_config.h"
#include "upf_u_arp.h"
#include "upf_u_icmp.h"
#include "upf_u_trtcm.h"

#define NF_TAG "upf_u"

/* Used for buffering */
#define DRAIN_CHUNK             128   /* max pkts dequeued per drain call */
#define SESS_DRAIN_SCAN_BUDGET   32   /* shared drain requests per callback */
#define SESS_DRAIN_BITMAP_WORDS  ((SESS_BUF_MAX_USERS + 63) / 64)

/* Used for non-blocking UE token-bucket shaping */
#define SHAPER_SCAN_BUDGET       32
#define SHAPER_DRAIN_BUDGET      128
#define SHAPER_INLINE_DRAIN_BUDGET 32
#define SHAPER_CLASS_BURST        16
#define SHAPER_MAX_QUEUE_DELAY_MS 100
#define SHAPER_MIN_QUEUE_PKTS     4
#define SHAPER_MAX_FLOWS_PER_UE  64
#define SHAPER_MAX_PKTS_PER_FLOW 512
#define SHAPER_MAX_PKTS_PER_UE   2048
#define SHAPER_ENTRY_POOL_CACHE  256
#define SHAPER_UE_BITMAP_WORDS   ((MAX_UE + 63) / 64)

uint64_t seid = 0;
uint16_t pdrId = 0;

enum shaper_decision {
    SHAPER_PASS = 0,
    SHAPER_QUEUED,
    SHAPER_DROP
};

enum shaper_pkt_color {
    SHAPER_COLOR_NQOS = 0,
    SHAPER_COLOR_GREEN,
    SHAPER_COLOR_YELLOW
};

enum shaper_active_list_id {
    SHAPER_ACTIVE_NONE = 0,
    SHAPER_ACTIVE_GREEN,
    SHAPER_ACTIVE_YELLOW,
    SHAPER_ACTIVE_NQOS,
    SHAPER_ACTIVE_COUNT
};

struct shaper_flow_key {
    uint32_t ue_ip;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t proto;
    uint8_t qfi;
    uint8_t is_qos;
};

struct shaper_entry {
    struct rte_mbuf *pkt;
    uint32_t pkt_len;
    uint16_t destination;
    enum shaper_pkt_color color;
    struct shaper_entry *next;
};

struct shaper_flow {
    bool in_use;
    struct shaper_flow_key key;
    struct shaper_entry *head;
    struct shaper_entry *tail;
    uint32_t queued_pkts;
    uint32_t queued_bytes;
    enum shaper_active_list_id active_list;
    uint64_t last_active_tsc;
    TAILQ_ENTRY(shaper_flow) active_node;
};

TAILQ_HEAD(shaper_flow_head, shaper_flow);

struct ue_shaper {
    rte_spinlock_t lock;
    struct shaper_flow flows[SHAPER_MAX_FLOWS_PER_UE];
    struct shaper_flow_head active[SHAPER_ACTIVE_COUNT];
    uint32_t active_count[SHAPER_ACTIVE_COUNT];
    uint32_t queued_pkts;
    uint8_t next_excess_is_yellow;
};

static struct ue_shaper g_ue_shaper[MAX_UE];
static struct rte_mempool *g_shaper_entry_pool;
static uint64_t g_shaper_active_ue_bitmap[SHAPER_UE_BITMAP_WORDS];
static uint32_t g_shaper_active_ue_cursor;
static uint64_t g_shaper_queued;
static uint64_t g_shaper_drained;
static uint64_t g_shaper_drop_invalid;
static uint64_t g_shaper_drop_red;
static uint64_t g_shaper_drop_green_overflow;
static uint64_t g_shaper_drop_yellow_overflow;
static uint64_t g_shaper_drop_nqos_overflow;
static uint64_t g_shaper_drop_flow_table_full;
static uint64_t g_shaper_drop_flow_queue_full;
static uint64_t g_shaper_drop_ue_queue_full;
static uint64_t g_shaper_drop_mempool_empty;
static uint64_t g_sess_drain_bitmap[SESS_DRAIN_BITMAP_WORDS];
static uint32_t g_sess_drain_scan_cursor;
static uint32_t g_sess_drain_active_count;
static uint64_t g_sess_buffer_queued;
static uint64_t g_sess_buffer_drained;
static uint64_t g_sess_buffer_full_drops;
static uint64_t g_sess_buffer_deferred_forw;
static uint64_t g_sess_buffer_far_conflict_drops;

static inline void
mark_session_drain_active(int sess_idx) {
    uint32_t word_idx;
    uint64_t bit;

    if (sess_idx < 0 || sess_idx >= SESS_BUF_MAX_USERS)
        return;
    word_idx = (uint32_t)sess_idx / 64;
    bit = 1ULL << ((uint32_t)sess_idx & 63);
    if ((g_sess_drain_bitmap[word_idx] & bit) == 0) {
        g_sess_drain_bitmap[word_idx] |= bit;
        g_sess_drain_active_count++;
    }
}

static inline void
clear_session_drain_active(int sess_idx) {
    uint32_t word_idx;
    uint64_t bit;

    if (sess_idx < 0 || sess_idx >= SESS_BUF_MAX_USERS)
        return;
    word_idx = (uint32_t)sess_idx / 64;
    bit = 1ULL << ((uint32_t)sess_idx & 63);
    if (g_sess_drain_bitmap[word_idx] & bit) {
        g_sess_drain_bitmap[word_idx] &= ~bit;
        if (g_sess_drain_active_count > 0)
            g_sess_drain_active_count--;
    }
}

typedef struct {
    void    *ptr;          // current active snapshot (cls_handle_t*)
    uint32_t ver;          // last applied version
    uint32_t pending_ver;  // version announced by UPF-C via REQ
    uint8_t  flip_pending; // 1 when a flip is requested; cleared after flip
} upf_cls_local_t;

static upf_cls_local_t g_cls_local = {0};

// Flip to the latest published snapshot (called at burst boundary)
static inline void
UpfClsMaybeFlipAndAck(void) {
    if (likely(!g_cls_local.flip_pending))
        return;

    // Seqlock read: accept only a stable, even version that doesn't change
    void *new_ptr = NULL;
    uint32_t v1, v2;

    for (;;) {
        v1 = __atomic_load_n(&g_upf_cls_ctrl->version, __ATOMIC_ACQUIRE);
        if (unlikely(v1 & 1u)) {          // writer in progress
            rte_pause();                   // be polite to the core
            continue;
        }

        // Load pointer after seeing an even version
        new_ptr  = __atomic_load_n((void * const *)&g_upf_cls_ctrl->active, __ATOMIC_ACQUIRE);

        // Re-check version; must be the same even number
        v2 = __atomic_load_n(&g_upf_cls_ctrl->version, __ATOMIC_ACQUIRE);
        if (likely(v1 == v2 && !(v2 & 1u)))
            break;

        // Changed under us; retry
        rte_pause();
    }

    if (unlikely(!new_ptr)) {
        UTLT_Warning("CLS flip requested but ctrl.active==NULL (ctrl.ver=%u)", v2);
        return;
    }

    // Commit locally & ACK the exact stable version observed
    g_cls_local.ptr  = new_ptr;
    g_cls_local.ver  = v2;
    g_cls_local.flip_pending = 0;

    (void)UpfSendEvt1(UPF_C_SERVICE_ID, EVT_CLS_GC_ACK, (uintptr_t)v2);
}


/* static inline const UPDK_PDR *
UpfLookupPdr(const ps_packet_t *key) {
    const cls_handle_t *snap = (const cls_handle_t *)g_cls_local.ptr;
    if (unlikely(!snap)) return NULL;

    uint32_t  precedence = 0;
    uintptr_t cookie     = 0;
    int hit = cls_classify_packet((cls_handle_t *)snap, key, &precedence, &cookie);
    if (!hit) return NULL;

    return (const UPDK_PDR *)cookie;
} */

static inline uint16_t
UpfClassifyGetPdrId(const ps_packet_t *key) {
    const cls_handle_t *snap = (const cls_handle_t *)g_cls_local.ptr;
    if (unlikely(!snap)) {
        UTLT_Warning("CLS classify: no snapshot yet (ver=%u) — dropping", g_cls_local.ver);
        return 0;
    }

    // logging block
    void *engine = *(void**)snap;
    UTLT_Debug("CLS classify: snap=%p engine=%p ver=%u", (void*)snap, engine, g_cls_local.ver);

    uint32_t  precedence = 0;
    uintptr_t pdrId     = 0;
    int hit = cls_classify_packet((cls_handle_t *)snap, key, &precedence, &pdrId);
    if (hit != 1) {
        return 0;
    }

    return (uint16_t)pdrId;
}

static inline const UPDK_PDR *
UpfClassifyGetPdrPtr(const ps_packet_t *key) {
    const cls_handle_t *snap = (const cls_handle_t *)g_cls_local.ptr;
    if (unlikely(!snap)) {
        UTLT_Warning("CLS classify: no snapshot yet (ver=%u) — dropping", g_cls_local.ver);
        return NULL;
    }
    uint32_t  precedence = 0;
    uintptr_t descriptor     = 0;
    int hit = cls_classify_packet((cls_handle_t *)snap, key, &precedence, &descriptor);
    if (hit != 1 || descriptor == 0) return NULL;
    return (const UPDK_PDR *)descriptor;
}

static int
shaper_init_entry_pool(struct onvm_nf *nf) {
    char name[64];
    uint64_t entry_count64 = (uint64_t)MAX_UE * SHAPER_MAX_PKTS_PER_UE;
    unsigned int entry_count;
    uint16_t instance_id = nf ? nf->instance_id : 0;

    if (g_shaper_entry_pool != NULL)
        return 0;

    if (entry_count64 == 0 || entry_count64 > UINT_MAX) {
        UTLT_Error("Invalid shaper entry pool size: %" PRIu64,
                   entry_count64);
        return -1;
    }
    entry_count = (unsigned int)entry_count64;

    snprintf(name, sizeof(name), "us_entry_%03u", instance_id);
    g_shaper_entry_pool = rte_mempool_lookup(name);
    if (g_shaper_entry_pool != NULL)
        return 0;

    g_shaper_entry_pool = rte_mempool_create(name, entry_count,
                                             sizeof(struct shaper_entry),
                                             SHAPER_ENTRY_POOL_CACHE, 0,
                                             NULL, NULL, NULL, NULL,
                                             SOCKET_ID_ANY, 0);
    if (g_shaper_entry_pool == NULL)
        g_shaper_entry_pool = rte_mempool_lookup(name);
    if (g_shaper_entry_pool == NULL) {
        UTLT_Error("Failed to create shaper entry pool %s", name);
        return -1;
    }
    return 0;
}

static void
shaper_init_state(void) {
    for (uint32_t word_idx = 0; word_idx < SHAPER_UE_BITMAP_WORDS; word_idx++)
        __atomic_store_n(&g_shaper_active_ue_bitmap[word_idx], 0,
                         __ATOMIC_RELEASE);
    g_shaper_active_ue_cursor = 0;

    for (int ue_idx = 0; ue_idx < MAX_UE; ue_idx++) {
        rte_spinlock_init(&g_ue_shaper[ue_idx].lock);
        for (int list_id = 0; list_id < SHAPER_ACTIVE_COUNT; list_id++)
            TAILQ_INIT(&g_ue_shaper[ue_idx].active[list_id]);
        g_ue_shaper[ue_idx].next_excess_is_yellow = 1;
    }
}

static inline void
shaper_free_entry(struct shaper_entry *entry) {
    if (entry != NULL && g_shaper_entry_pool != NULL)
        rte_mempool_put(g_shaper_entry_pool, entry);
}

static inline uint64_t
shaper_ue_bitmap_valid_mask(uint32_t word_idx) {
    uint32_t used_bits;

    if (word_idx + 1 < SHAPER_UE_BITMAP_WORDS)
        return UINT64_MAX;

    used_bits = MAX_UE & 63;
    return used_bits == 0 ? UINT64_MAX : ((1ULL << used_bits) - 1);
}

static inline void
shaper_mark_ue_active(int ue_idx) {
    uint32_t word_idx = (uint32_t)ue_idx / 64;
    uint64_t bit = 1ULL << ((uint32_t)ue_idx & 63);

    __atomic_fetch_or(&g_shaper_active_ue_bitmap[word_idx], bit,
                      __ATOMIC_RELEASE);
}

static inline void
shaper_clear_ue_active(int ue_idx) {
    uint32_t word_idx = (uint32_t)ue_idx / 64;
    uint64_t bit = 1ULL << ((uint32_t)ue_idx & 63);

    __atomic_fetch_and(&g_shaper_active_ue_bitmap[word_idx], ~bit,
                       __ATOMIC_RELEASE);
}

static int
shaper_next_active_ue(const uint64_t *skip_bitmap) {
    uint32_t start = g_shaper_active_ue_cursor % MAX_UE;
    uint32_t start_word = start / 64;
    uint32_t start_bit = start & 63;

    for (uint32_t pass = 0; pass < 2; pass++) {
        uint32_t first_word = pass == 0 ? start_word : 0;
        uint32_t last_word = pass == 0 ? SHAPER_UE_BITMAP_WORDS
                                       : start_word + 1;

        for (uint32_t word_idx = first_word; word_idx < last_word; word_idx++) {
            uint64_t word = __atomic_load_n(&g_shaper_active_ue_bitmap[word_idx],
                                            __ATOMIC_ACQUIRE);
            word &= shaper_ue_bitmap_valid_mask(word_idx);
            if (skip_bitmap != NULL)
                word &= ~skip_bitmap[word_idx];
            if (pass == 0 && word_idx == start_word) {
                if (start_bit > 0)
                    word &= UINT64_MAX << start_bit;
            } else if (pass == 1 && word_idx == start_word) {
                if (start_bit == 0)
                    word = 0;
                else
                    word &= (1ULL << start_bit) - 1;
            }
            if (word == 0)
                continue;

            uint32_t bit = (uint32_t)__builtin_ctzll(word);
            uint32_t ue_idx = word_idx * 64 + bit;
            g_shaper_active_ue_cursor = (ue_idx + 1) % MAX_UE;
            return (int)ue_idx;
        }
    }

    return -1;
}

static inline bool
shaper_flow_key_equal(const struct shaper_flow_key *a,
                      const struct shaper_flow_key *b) {
    return a->ue_ip == b->ue_ip &&
           a->src_ip == b->src_ip &&
           a->dst_ip == b->dst_ip &&
           a->src_port == b->src_port &&
           a->dst_port == b->dst_port &&
           a->proto == b->proto &&
           a->qfi == b->qfi &&
           a->is_qos == b->is_qos;
}

static inline uint32_t
shaper_flow_hash(const struct shaper_flow_key *key) {
    uint32_t h = 2166136261u;

    h = (h ^ key->ue_ip) * 16777619u;
    h = (h ^ key->src_ip) * 16777619u;
    h = (h ^ key->dst_ip) * 16777619u;
    h = (h ^ (((uint32_t)key->src_port << 16) | key->dst_port)) * 16777619u;
    h = (h ^ (((uint32_t)key->proto << 16) |
              ((uint32_t)key->qfi << 8) | key->is_qos)) * 16777619u;
    return h;
}

static struct shaper_flow *
shaper_lookup_flow(struct ue_shaper *ue, const struct shaper_flow_key *key,
                   bool create) {
    uint32_t start = shaper_flow_hash(key) % SHAPER_MAX_FLOWS_PER_UE;
    int free_idx = -1;

    for (uint32_t probe = 0; probe < SHAPER_MAX_FLOWS_PER_UE; probe++) {
        uint32_t idx = (start + probe) % SHAPER_MAX_FLOWS_PER_UE;
        struct shaper_flow *flow = &ue->flows[idx];

        if (flow->in_use) {
            if (shaper_flow_key_equal(&flow->key, key))
                return flow;
            continue;
        }
        if (free_idx < 0)
            free_idx = (int)idx;
    }

    if (!create || free_idx < 0)
        return NULL;

    struct shaper_flow *flow = &ue->flows[free_idx];
    memset(flow, 0, sizeof(*flow));
    flow->in_use = true;
    flow->key = *key;
    flow->active_list = SHAPER_ACTIVE_NONE;
    return flow;
}

static inline enum shaper_active_list_id
shaper_active_list_for_head(const struct shaper_flow *flow) {
    if (flow == NULL || flow->head == NULL)
        return SHAPER_ACTIVE_NONE;
    if (!flow->key.is_qos)
        return SHAPER_ACTIVE_NQOS;
    switch (flow->head->color) {
    case SHAPER_COLOR_GREEN:
        return SHAPER_ACTIVE_GREEN;
    case SHAPER_COLOR_YELLOW:
        return SHAPER_ACTIVE_YELLOW;
    default:
        return SHAPER_ACTIVE_NONE;
    }
}

static inline void
shaper_activate_flow(struct ue_shaper *ue, struct shaper_flow *flow) {
    enum shaper_active_list_id list_id = shaper_active_list_for_head(flow);

    if (list_id == SHAPER_ACTIVE_NONE)
        return;

    if (flow->active_list != SHAPER_ACTIVE_NONE) {
        TAILQ_REMOVE(&ue->active[flow->active_list], flow, active_node);
        ue->active_count[flow->active_list]--;
    }
    TAILQ_INSERT_TAIL(&ue->active[list_id], flow, active_node);
    ue->active_count[list_id]++;
    flow->active_list = list_id;
    flow->last_active_tsc = rte_get_tsc_cycles();
}

static inline void
shaper_deactivate_flow(struct ue_shaper *ue, struct shaper_flow *flow) {
    if (flow->active_list == SHAPER_ACTIVE_NONE)
        return;
    TAILQ_REMOVE(&ue->active[flow->active_list], flow, active_node);
    ue->active_count[flow->active_list]--;
    flow->active_list = SHAPER_ACTIVE_NONE;
}

static inline void
shaper_release_empty_flow(struct ue_shaper *ue, struct shaper_flow *flow) {
    shaper_deactivate_flow(ue, flow);
    memset(flow, 0, sizeof(*flow));
}

static inline void
shaper_count_overflow(enum shaper_pkt_color color) {
    if (color == SHAPER_COLOR_GREEN)
        __atomic_fetch_add(&g_shaper_drop_green_overflow, 1, __ATOMIC_RELAXED);
    else if (color == SHAPER_COLOR_YELLOW)
        __atomic_fetch_add(&g_shaper_drop_yellow_overflow, 1, __ATOMIC_RELAXED);
    else
        __atomic_fetch_add(&g_shaper_drop_nqos_overflow, 1, __ATOMIC_RELAXED);
}

static void
shaper_drop_head_locked(struct ue_shaper *ue, struct shaper_flow *flow) {
    struct shaper_entry *entry;

    if (ue == NULL || flow == NULL || flow->head == NULL)
        return;

    entry = flow->head;
    flow->head = entry->next;
    if (flow->head == NULL)
        flow->tail = NULL;
    flow->queued_pkts--;
    flow->queued_bytes -= entry->pkt_len;
    ue->queued_pkts--;

    rte_pktmbuf_free(entry->pkt);
    shaper_count_overflow(entry->color);
    shaper_free_entry(entry);
    __atomic_fetch_add(&g_shaper_drop_flow_queue_full, 1,
                       __ATOMIC_RELAXED);
}

static void
shaper_trim_flow_for_enqueue_locked(struct ue_shaper *ue,
                                    struct shaper_flow *flow,
                                    uint32_t pkt_len,
                                    uint64_t queue_limit_bytes) {
    bool was_active;

    if (ue == NULL || flow == NULL || flow->queued_pkts == 0)
        return;

    was_active = flow->active_list != SHAPER_ACTIVE_NONE;
    if (was_active)
        shaper_deactivate_flow(ue, flow);

    while (flow->head != NULL &&
           (flow->queued_pkts >= SHAPER_MAX_PKTS_PER_FLOW ||
            (uint64_t)flow->queued_bytes + pkt_len > queue_limit_bytes)) {
        shaper_drop_head_locked(ue, flow);
    }

    if (flow->head != NULL)
        shaper_activate_flow(ue, flow);
}

static inline bool
shaper_class_has_backlog_locked(const struct ue_shaper *ue,
                                enum ue_bucket_class bucket_class) {
    switch (bucket_class) {
    case UE_BUCKET_GREEN:
        return ue->active_count[SHAPER_ACTIVE_GREEN] > 0;
    case UE_BUCKET_YELLOW:
    case UE_BUCKET_NQOS:
        return ue->active_count[SHAPER_ACTIVE_GREEN] > 0 ||
               ue->active_count[SHAPER_ACTIVE_YELLOW] > 0 ||
               ue->active_count[SHAPER_ACTIVE_NQOS] > 0;
    default:
        return false;
    }
}

static inline enum ue_bucket_class
shaper_bucket_for_packet(bool is_qos, enum shaper_pkt_color color) {
    if (!is_qos)
        return UE_BUCKET_NQOS;
    if (color == SHAPER_COLOR_GREEN)
        return UE_BUCKET_GREEN;
    if (color == SHAPER_COLOR_YELLOW)
        return UE_BUCKET_YELLOW;
    return UE_BUCKET_NQOS;
}

static enum shaper_decision
shape_or_enqueue_packet(int ue_idx, const struct shaper_flow_key *key,
                        bool is_qos, enum shaper_pkt_color color,
                        struct rte_mbuf *pkt, uint32_t pkt_len,
                        struct onvm_pkt_meta *meta) {
    struct ue_shaper *ue;
    struct shaper_flow *flow;
    struct shaper_entry *entry;
    enum ue_bucket_class bucket_class =
        shaper_bucket_for_packet(is_qos, color);
    uint64_t min_queue_bytes;
    uint64_t queue_limit_bytes;

    if (unlikely(pkt == NULL || key == NULL || g_shaper_entry_pool == NULL)) {
        meta->action = ONVM_NF_ACTION_DROP;
        shaper_count_overflow(color);
        return SHAPER_DROP;
    }
    min_queue_bytes = (uint64_t)pkt_len * SHAPER_MIN_QUEUE_PKTS;

    if (!ueBucketCanFitPacket(ue_idx, bucket_class, pkt_len)) {
        meta->action = ONVM_NF_ACTION_DROP;
        __atomic_fetch_add(&g_shaper_drop_invalid, 1, __ATOMIC_RELAXED);
        return SHAPER_DROP;
    }

    queue_limit_bytes =
        ueShaperQueueLimitBytes(ue_idx, is_qos,
                                SHAPER_MAX_QUEUE_DELAY_MS,
                                min_queue_bytes);

    ue = &g_ue_shaper[ue_idx];
    rte_spinlock_lock(&ue->lock);

    flow = shaper_lookup_flow(ue, key, false);
    if (flow == NULL &&
        !shaper_class_has_backlog_locked(ue, bucket_class) &&
        consumeUeBucketTokens(ue_idx, bucket_class, pkt_len)) {
        rte_spinlock_unlock(&ue->lock);
        return SHAPER_PASS;
    }

    if (flow == NULL)
        flow = shaper_lookup_flow(ue, key, true);
    if (flow == NULL) {
        rte_spinlock_unlock(&ue->lock);
        meta->action = ONVM_NF_ACTION_DROP;
        __atomic_fetch_add(&g_shaper_drop_flow_table_full, 1,
                           __ATOMIC_RELAXED);
        shaper_count_overflow(color);
        return SHAPER_DROP;
    }
    shaper_trim_flow_for_enqueue_locked(ue, flow, pkt_len,
                                        queue_limit_bytes);
    if (flow->queued_pkts >= SHAPER_MAX_PKTS_PER_FLOW) {
        rte_spinlock_unlock(&ue->lock);
        meta->action = ONVM_NF_ACTION_DROP;
        __atomic_fetch_add(&g_shaper_drop_flow_queue_full, 1,
                           __ATOMIC_RELAXED);
        shaper_count_overflow(color);
        return SHAPER_DROP;
    }
    if (ue->queued_pkts >= SHAPER_MAX_PKTS_PER_UE) {
        if (flow->queued_pkts == 0)
            shaper_release_empty_flow(ue, flow);
        rte_spinlock_unlock(&ue->lock);
        meta->action = ONVM_NF_ACTION_DROP;
        __atomic_fetch_add(&g_shaper_drop_ue_queue_full, 1,
                           __ATOMIC_RELAXED);
        shaper_count_overflow(color);
        return SHAPER_DROP;
    }
    if (rte_mempool_get(g_shaper_entry_pool, (void **)&entry) != 0) {
        if (flow->queued_pkts == 0)
            shaper_release_empty_flow(ue, flow);
        rte_spinlock_unlock(&ue->lock);
        meta->action = ONVM_NF_ACTION_DROP;
        __atomic_fetch_add(&g_shaper_drop_mempool_empty, 1,
                           __ATOMIC_RELAXED);
        shaper_count_overflow(color);
        return SHAPER_DROP;
    }

    entry->pkt = pkt;
    entry->pkt_len = pkt_len;
    entry->destination = meta->destination;
    entry->color = color;
    entry->next = NULL;

    rte_mbuf_refcnt_update(pkt, 1);
    if (flow->tail != NULL)
        flow->tail->next = entry;
    else
        flow->head = entry;
    flow->tail = entry;
    flow->queued_pkts++;
    flow->queued_bytes += pkt_len;
    ue->queued_pkts++;

    if (flow->queued_pkts == 1)
        shaper_activate_flow(ue, flow);
    shaper_mark_ue_active(ue_idx);

    rte_spinlock_unlock(&ue->lock);

    __atomic_fetch_add(&g_shaper_queued, 1, __ATOMIC_RELAXED);
    meta->action = ONVM_NF_ACTION_DROP;
    return SHAPER_QUEUED;
}

static bool
shaper_drain_one_from_list_locked(int ue_idx,
                                  enum shaper_active_list_id list_id,
                                  enum ue_bucket_class bucket_class,
                                  struct rte_mbuf **tx_buf,
                                  uint32_t *nb_tx,
                                  struct onvm_configuration *onvm_config) {
    struct ue_shaper *ue = &g_ue_shaper[ue_idx];
    uint32_t attempts = ue->active_count[list_id];

    while (attempts-- > 0) {
        struct shaper_flow *flow = TAILQ_FIRST(&ue->active[list_id]);
        struct shaper_entry *entry;
        struct rte_mbuf *pkt;

        if (flow == NULL)
            return false;

        shaper_deactivate_flow(ue, flow);
        entry = flow->head;
        if (entry == NULL) {
            shaper_release_empty_flow(ue, flow);
            continue;
        }

        if (!ueBucketCanFitPacket(ue_idx, bucket_class, entry->pkt_len)) {
            flow->head = entry->next;
            if (flow->head == NULL)
                flow->tail = NULL;
            flow->queued_pkts--;
            flow->queued_bytes -= entry->pkt_len;
            ue->queued_pkts--;
            rte_pktmbuf_free(entry->pkt);
            shaper_free_entry(entry);
            __atomic_fetch_add(&g_shaper_drop_invalid, 1, __ATOMIC_RELAXED);
            if (flow->head != NULL)
                shaper_activate_flow(ue, flow);
            else
                shaper_release_empty_flow(ue, flow);
            continue;
        }

        if (!consumeUeBucketTokens(ue_idx, bucket_class, entry->pkt_len)) {
            shaper_activate_flow(ue, flow);
            continue;
        }

        flow->head = entry->next;
        if (flow->head == NULL)
            flow->tail = NULL;
        flow->queued_pkts--;
        flow->queued_bytes -= entry->pkt_len;
        ue->queued_pkts--;

        pkt = entry->pkt;
        struct onvm_pkt_meta *m =
            onvm_get_pkt_meta(pkt, onvm_config->dynfield_offset);
        m->action = ONVM_NF_ACTION_OUT;
        m->destination = entry->destination;
        tx_buf[(*nb_tx)++] = pkt;

        shaper_free_entry(entry);
        if (flow->head != NULL)
            shaper_activate_flow(ue, flow);
        else
            shaper_release_empty_flow(ue, flow);

        __atomic_fetch_add(&g_shaper_drained, 1, __ATOMIC_RELAXED);
        return true;
    }

    return false;
}

static uint32_t
shaper_drain_service_locked(int ue_idx,
                            enum shaper_active_list_id list_id,
                            enum ue_bucket_class bucket_class,
                            struct rte_mbuf **tx_buf,
                            uint32_t *nb_tx,
                            struct onvm_configuration *onvm_config,
                            uint32_t budget) {
    uint32_t sent = 0;

    while (sent < budget &&
           g_ue_shaper[ue_idx].active_count[list_id] > 0) {
        if (!shaper_drain_one_from_list_locked(ue_idx, list_id,
                                               bucket_class, tx_buf, nb_tx,
                                               onvm_config))
            break;
        sent++;
    }

    return sent;
}

static uint32_t
shaper_drain_green_locked(int ue_idx, struct rte_mbuf **tx_buf,
                          uint32_t *nb_tx,
                          struct onvm_configuration *onvm_config,
                          uint32_t budget) {
    return shaper_drain_service_locked(ue_idx, SHAPER_ACTIVE_GREEN,
                                       UE_BUCKET_GREEN, tx_buf, nb_tx,
                                       onvm_config, budget);
}

static uint32_t
shaper_drain_excess_locked(int ue_idx, struct rte_mbuf **tx_buf,
                           uint32_t *nb_tx,
                           struct onvm_configuration *onvm_config,
                           uint32_t budget) {
    struct ue_shaper *ue = &g_ue_shaper[ue_idx];
    uint32_t sent = 0;

    while (sent < budget &&
           (ue->active_count[SHAPER_ACTIVE_YELLOW] > 0 ||
            ue->active_count[SHAPER_ACTIVE_NQOS] > 0)) {
        bool prefer_yellow = ue->next_excess_is_yellow != 0;
        enum shaper_active_list_id list_id = prefer_yellow ?
            SHAPER_ACTIVE_YELLOW : SHAPER_ACTIVE_NQOS;
        enum ue_bucket_class bucket_class = prefer_yellow ?
            UE_BUCKET_YELLOW : UE_BUCKET_NQOS;
        uint32_t n;

        n = shaper_drain_service_locked(ue_idx, list_id, bucket_class,
                                        tx_buf, nb_tx, onvm_config, 1);
        ue->next_excess_is_yellow = !ue->next_excess_is_yellow;
        if (n == 0) {
            list_id = prefer_yellow ? SHAPER_ACTIVE_NQOS :
                                      SHAPER_ACTIVE_YELLOW;
            bucket_class = prefer_yellow ? UE_BUCKET_NQOS :
                                           UE_BUCKET_YELLOW;
            n = shaper_drain_service_locked(ue_idx, list_id, bucket_class,
                                            tx_buf, nb_tx, onvm_config, 1);
            if (n == 0)
                break;
        }
        sent += n;
    }

    return sent;
}

static uint32_t
drain_ue_shaper(int ue_idx, struct onvm_nf *nf, uint32_t budget) {
    struct rte_mbuf *tx_buf[DRAIN_CHUNK];
    struct onvm_configuration *onvm_config;
    struct ue_shaper *ue;
    uint32_t nb_tx = 0;
    uint32_t total = 0;

    if (ue_idx < 0 || ue_idx >= MAX_UE || nf == NULL || budget == 0)
        return 0;

    ue = &g_ue_shaper[ue_idx];
    onvm_config = onvm_nflib_get_onvm_config();
    rte_spinlock_lock(&ue->lock);
    if (ue->queued_pkts == 0) {
        shaper_clear_ue_active(ue_idx);
        rte_spinlock_unlock(&ue->lock);
        return 0;
    }

    while (budget > 0 && nb_tx < DRAIN_CHUNK && ue->queued_pkts > 0) {
        bool sent = false;
        uint32_t tx_room = DRAIN_CHUNK - nb_tx;
        uint32_t burst = RTE_MIN(budget, (uint32_t)SHAPER_CLASS_BURST);
        uint32_t n;

        burst = RTE_MIN(burst, tx_room);
        if (burst == 0)
            break;

        n = shaper_drain_green_locked(ue_idx, tx_buf, &nb_tx,
                                      onvm_config, burst);
        if (n > 0) {
            total += n;
            budget -= n;
            sent = true;
            if (budget == 0 || nb_tx == DRAIN_CHUNK)
                break;
        }

        tx_room = DRAIN_CHUNK - nb_tx;
        burst = RTE_MIN(budget, (uint32_t)SHAPER_CLASS_BURST);
        burst = RTE_MIN(burst, tx_room);
        if (burst == 0)
            break;

        n = shaper_drain_excess_locked(ue_idx, tx_buf, &nb_tx,
                                       onvm_config, burst);
        if (n > 0) {
            total += n;
            budget -= n;
            sent = true;
        }

        if (!sent)
            break;
    }
    if (ue->queued_pkts == 0)
        shaper_clear_ue_active(ue_idx);
    else
        shaper_mark_ue_active(ue_idx);
    rte_spinlock_unlock(&ue->lock);

    if (nb_tx > 0) {
        onvm_pkt_process_tx_batch(nf->nf_tx_mgr, tx_buf,
                                  onvm_config->dynfield_offset, nb_tx, nf);
        onvm_pkt_enqueue_tx_thread(nf->nf_tx_mgr->to_tx_buf, nf);
    }
    return total;
}

static uint32_t
drain_shaper_queues_budget(struct onvm_nf *nf, uint32_t budget) {
    uint64_t tried_ue_bitmap[SHAPER_UE_BITMAP_WORDS] = {0};
    uint32_t total = 0;

    for (uint32_t visited = 0; visited < SHAPER_SCAN_BUDGET && budget > 0; visited++) {
        int ue_idx = shaper_next_active_ue(tried_ue_bitmap);
        uint32_t drained;

        if (ue_idx < 0)
            break;

        tried_ue_bitmap[(uint32_t)ue_idx / 64] |=
            1ULL << ((uint32_t)ue_idx & 63);
        drained = drain_ue_shaper(ue_idx, nf, budget);
        total += drained;
        budget -= drained;
    }

    return total;
}

static uint32_t
drain_shaper_queues(struct onvm_nf *nf) {
    return drain_shaper_queues_budget(nf, SHAPER_DRAIN_BUDGET);
}

static void
shaper_cleanup(void) {
    for (int ue_idx = 0; ue_idx < MAX_UE; ue_idx++) {
        struct ue_shaper *ue = &g_ue_shaper[ue_idx];

        rte_spinlock_lock(&ue->lock);
        for (int flow_idx = 0; flow_idx < SHAPER_MAX_FLOWS_PER_UE; flow_idx++) {
            struct shaper_flow *flow = &ue->flows[flow_idx];
            struct shaper_entry *entry = flow->head;

            while (entry != NULL) {
                struct shaper_entry *next = entry->next;
                if (entry->pkt != NULL)
                    rte_pktmbuf_free(entry->pkt);
                shaper_free_entry(entry);
                entry = next;
            }
            memset(flow, 0, sizeof(*flow));
        }
        ue->queued_pkts = 0;
        ue->next_excess_is_yellow = 1;
        for (int list_id = 0; list_id < SHAPER_ACTIVE_COUNT; list_id++) {
            TAILQ_INIT(&ue->active[list_id]);
            ue->active_count[list_id] = 0;
        }
        rte_spinlock_unlock(&ue->lock);
    }
    for (uint32_t word_idx = 0; word_idx < SHAPER_UE_BITMAP_WORDS; word_idx++)
        __atomic_store_n(&g_shaper_active_ue_bitmap[word_idx], 0,
                         __ATOMIC_RELEASE);
    g_shaper_active_ue_cursor = 0;
}

static bool
build_dl_shaper_flow_key(struct rte_mbuf *pkt, const UPDK_PDR *pdr,
                         uint32_t ue_ip, bool is_qos,
                         struct shaper_flow_key *key) {
    struct rte_ipv4_hdr *iph;
    uint16_t l4_off;
    uint32_t pkt_len;

    if (pkt == NULL || key == NULL)
        return false;

    iph = onvm_pkt_ipv4_hdr(pkt);
    if (iph == NULL || ((iph->version_ihl >> 4) != 4))
        return false;

    memset(key, 0, sizeof(*key));
    key->ue_ip = ue_ip;
    key->src_ip = rte_be_to_cpu_32(iph->src_addr);
    key->dst_ip = rte_be_to_cpu_32(iph->dst_addr);
    key->proto = iph->next_proto_id;
    key->is_qos = is_qos ? 1 : 0;
    key->qfi = (is_qos && pdr != NULL && pdr->qer != NULL) ?
               QERGetQFI(pdr->qer) : 0;

    l4_off = sizeof(struct rte_ether_hdr) +
             ((iph->version_ihl & 0x0f) * 4);
    pkt_len = rte_pktmbuf_pkt_len(pkt);
    if (key->proto == IPPROTO_UDP &&
        pkt_len >= l4_off + sizeof(struct rte_udp_hdr)) {
        struct rte_udp_hdr udp_hdr;
        const struct rte_udp_hdr *uh =
            rte_pktmbuf_read(pkt, l4_off, sizeof(udp_hdr), &udp_hdr);
        if (uh == NULL)
            return false;
        key->src_port = rte_be_to_cpu_16(uh->src_port);
        key->dst_port = rte_be_to_cpu_16(uh->dst_port);
    } else if (key->proto == IPPROTO_TCP &&
               pkt_len >= l4_off + sizeof(struct rte_tcp_hdr)) {
        struct rte_tcp_hdr tcp_hdr;
        const struct rte_tcp_hdr *th =
            rte_pktmbuf_read(pkt, l4_off, sizeof(tcp_hdr), &tcp_hdr);
        if (th == NULL)
            return false;
        key->src_port = rte_be_to_cpu_16(th->src_port);
        key->dst_port = rte_be_to_cpu_16(th->dst_port);
    }

    return true;
}

static bool
dl_qos_packet_len(struct rte_mbuf *pkt, const struct rte_ipv4_hdr *iph,
                  uint32_t *metered_len) {
    uint16_t ip_total_len;
    uint16_t ip_hdr_len;
    uint16_t l4_payload_len;
    uint16_t l4_off;
    uint32_t pkt_len;

    if (metered_len != NULL)
        *metered_len = 0;
    if (pkt == NULL || iph == NULL || metered_len == NULL)
        return false;

    ip_hdr_len = (uint16_t)((iph->version_ihl & 0x0f) * 4);
    ip_total_len = rte_be_to_cpu_16(iph->total_length);
    pkt_len = rte_pktmbuf_pkt_len(pkt);

    if (ip_hdr_len < sizeof(struct rte_ipv4_hdr) ||
        ip_total_len < ip_hdr_len ||
        pkt_len < sizeof(struct rte_ether_hdr) + ip_total_len)
        return false;

    l4_payload_len = ip_total_len - ip_hdr_len;
    l4_off = sizeof(struct rte_ether_hdr) + ip_hdr_len;

    if (iph->next_proto_id == IPPROTO_UDP) {
        if (l4_payload_len < sizeof(struct rte_udp_hdr))
            return false;
        *metered_len = l4_payload_len - sizeof(struct rte_udp_hdr);
        return true;
    }

    if (iph->next_proto_id == IPPROTO_TCP) {
        struct rte_tcp_hdr tcp_hdr;
        const struct rte_tcp_hdr *th;
        uint16_t tcp_hdr_len;

        if (l4_payload_len < sizeof(struct rte_tcp_hdr))
            return false;

        th = rte_pktmbuf_read(pkt, l4_off, sizeof(tcp_hdr), &tcp_hdr);
        if (th == NULL)
            return false;

        tcp_hdr_len = (uint16_t)((th->data_off >> 4) * 4);
        if (tcp_hdr_len < sizeof(struct rte_tcp_hdr) ||
            tcp_hdr_len > l4_payload_len)
            return false;

        *metered_len = l4_payload_len - tcp_hdr_len;
        return true;
    }

    *metered_len = l4_payload_len;
    return true;
}

static inline uint64_t
saturating_add_u64(uint64_t lhs, uint64_t rhs) {
    return UINT64_MAX - lhs < rhs ? UINT64_MAX : lhs + rhs;
}

UPDK_PDR *
GetPdrByUeIpAddress(struct rte_mbuf *pkt, uint32_t ue_ip)
{
    /* ── 1) Build classifier key ─────────────────────────────── */
    ps_packet_t key = {0};
    uint8_t *pkt_data = rte_pktmbuf_mtod(pkt, uint8_t *);

    /* Outer (N6 / Core) IPv4 + UDP */
    struct rte_ipv4_hdr *outer4 = onvm_pkt_ipv4_hdr(pkt);
    if (!outer4) return NULL;
    struct rte_udp_hdr  *outerU = onvm_pkt_udp_hdr(pkt);

    key.src_ip = rte_be_to_cpu_32(outer4->src_addr);
    key.dst_ip = rte_be_to_cpu_32(outer4->dst_addr);
    key.tos_tc = outer4->type_of_service;

    key.teid    = 0;        /* Downlink: no GTP */
    key.ue_ip   = ue_ip;

    uint16_t sp = 0, dp = 0;

    key.proto = outer4->next_proto_id;

    if (key.proto == IPPROTO_UDP) {
        const struct rte_udp_hdr *uh = onvm_pkt_udp_hdr(pkt);
        if (uh) {
            sp = rte_be_to_cpu_16(uh->src_port);
            dp = rte_be_to_cpu_16(uh->dst_port);
        }
    }

    key.src_port= sp;
    key.dst_port= dp;
    key.proto   = outer4->next_proto_id;

    /* SPI (ESP) */
    key.spi = 0;


    // Flow-label (only applicable to IPv6 traffic)
    key.flow_label = 0;
    key.ni_hash = 0;    // packet is not GTP‑encapsulated
    key.qfi = 0;        // no QFI in plain-IP downlink path

    //key.source_if = PortToSourceInterface(pkt->port);

    key.source_if = SRC_IF_CORE;
    key.is_uplink = false;

    /* ── 2) PartitionSort classifier ────────────────────────── */
    const UPDK_PDR *pdr = UpfClassifyGetPdrPtr(&key);
    if (!pdr) {
        UTLT_Error("Couldn't classify the packet to a PDR");
        return NULL;
    }

    ConfigureQerFlows(pdr, false);
    return pdr;
}

UPDK_PDR *
GetPdrByTeid(struct rte_mbuf *pkt, const gtp_parse_result_t *gtp_info) {
    // Locate inner IP header using pre-computed offset
    size_t inner_offset = sizeof(struct rte_ether_hdr) + gtp_info->outer_hdr_len;

    uint16_t data_len = rte_pktmbuf_data_len(pkt);
    if (data_len < inner_offset + sizeof(struct rte_ipv4_hdr)) return NULL;

    struct rte_ipv4_hdr *inner4 = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *, inner_offset);

    // Verify it looks like IPv4
    if ((inner4->version_ihl >> 4) != 4) return NULL;

    uint8_t inner_ihl = (inner4->version_ihl & 0x0F) * 4;
    struct rte_udp_hdr *innerU = rte_pktmbuf_mtod_offset(pkt, struct rte_udp_hdr *,
        inner_offset + inner_ihl);

    // Build classifier key using pre-parsed values
    ps_packet_t key = {0};
    key.teid      = gtp_info->teid;
    key.qfi       = gtp_info->qfi;
    key.ue_ip     = rte_be_to_cpu_32(inner4->src_addr);
    key.src_ip    = key.ue_ip;
    key.dst_ip    = rte_be_to_cpu_32(inner4->dst_addr);
    key.src_port  = rte_be_to_cpu_16(innerU->src_port);
    key.dst_port  = rte_be_to_cpu_16(innerU->dst_port);
    key.proto     = inner4->next_proto_id;
    key.tos_tc    = inner4->type_of_service;
    key.source_if = SRC_IF_ACCESS;
    key.is_uplink = true;

    /* ── PartitionSort classifier ──────────────────────────── */
    const UPDK_PDR *pdr = UpfClassifyGetPdrPtr(&key);
    if (!pdr) {
        UTLT_Error("Couldn't classify the packet to a PDR");
        return NULL;
    }

    ConfigureQerFlows(pdr, true);

    return pdr;
}

static inline void
AccumulateQerDlRates(const UPDK_QER *q, uint64_t *ambr64,
                     uint64_t *gbr64, uint64_t *mbr64,
                     bool *has_gbr_qer)
{
    if (!q || !q->flags.maximumBitrate)
        return;

    if (q->flags.guaranteedBitrate) {
        *has_gbr_qer = true;
        *gbr64 = saturating_add_u64(*gbr64, q->guaranteedBitrate.dl);
        *mbr64 = saturating_add_u64(*mbr64, q->maximumBitrate.dl);
        return;
    }

    if (q->maximumBitrate.dl > *ambr64)
        *ambr64 = q->maximumBitrate.dl;
}

static inline bool
GetQerRatesFromSession(UpfSession *session, uint64_t *ambr64,
                       uint64_t *gbr64, uint64_t *mbr64,
                       bool *has_gbr_qer)
{
    list_iterator_t *it;
    list_node_t *node;
    bool found = false;

    if (!session || !session->qer_list)
        return false;

    it = list_iterator_new(session->qer_list, LIST_HEAD);
    if (!it)
        return false;

    while ((node = list_iterator_next(it)) != NULL) {
        const UPDK_QER *q = (const UPDK_QER *)node->val;
        if (!q || !q->flags.maximumBitrate)
            continue;

        found = true;
        AccumulateQerDlRates(q, ambr64, gbr64, mbr64, has_gbr_qer);
    }

    list_iterator_destroy(it);
    return found;
}

static inline bool
GetQerRatesFromPdr(const UPDK_PDR *pdr, uint64_t *ambr64,
                   uint64_t *gbr64, uint64_t *mbr64,
                   bool *has_gbr_qer)
{
    bool found = false;

    if (!pdr || pdr->qer_count == 0)
        return false;

    int n = (int)pdr->qer_count;
    if (n > 2) n = 2; /* safety; struct currently supports 2 */

    for (int i = 0; i < n; i++) {
        const UPDK_QER *q = pdr->qers[i];
        if (!q || !q->flags.maximumBitrate)
            continue;

        found = true;
        AccumulateQerDlRates(q, ambr64, gbr64, mbr64, has_gbr_qer);
    }

    return found;
}

/* Populate UE table from the owning session when possible. The session-level
 * non-GBR QER carries AMBR; GBR-bearing QERs carry QoS flow GBR/MBR. */
static inline int
GetQerByUEIpAddressFromPdr(uint32_t ue_ip, UpfSession *session,
                           const UPDK_PDR *pdr, const char *ip_str)
{
    if ((!session || !session->qer_list) && (!pdr || pdr->qer_count == 0)) {
        UTLT_Trace("UE %s: No PDR or PDR has no QERs, skip UE table entry",
                   ip_str ? ip_str : "<unknown>");
        return -1;
    }

    uint64_t ambr64 = 0;
    uint64_t gbr64  = 0;
    uint64_t mbr64  = 0;
    bool has_gbr_qer = false;

    if (!GetQerRatesFromSession(session, &ambr64, &gbr64, &mbr64,
                                &has_gbr_qer)) {
        GetQerRatesFromPdr(pdr, &ambr64, &gbr64, &mbr64, &has_gbr_qer);
    }
    if (ambr64 == 0 && mbr64 > 0)
        ambr64 = mbr64;

    if (ambr64 == 0) {
        UTLT_Trace("UE %s: no DL MBR across PDR QERs, skip UE table entry",
                   ip_str ? ip_str : "<unknown>");
        return -1;
    }

    /* Clamp PFCP 64-bit rates into 32-bit UE table fields */
    uint32_t ambr = (ambr64 > UINT32_MAX) ? UINT32_MAX : (uint32_t)ambr64;
    uint32_t gbr  = (gbr64  > UINT32_MAX) ? UINT32_MAX : (uint32_t)gbr64;
    uint32_t mbr  = (mbr64  > UINT32_MAX) ? UINT32_MAX : (uint32_t)mbr64;

    if (!has_gbr_qer)
        mbr = 0;
    if (mbr && gbr > mbr) gbr = mbr;

    UTLT_Warning("Add UE IP: %s, AMBR: %u GBR: %u, MBR: %u",
                 ip_str ? ip_str : "<unknown>", ambr, gbr, mbr);

    return addEntrybyUeIp(ue_ip, ambr, gbr, mbr);
}


void
Encap(struct rte_mbuf *pkt, UPDK_FAR *far, UPDK_QER *qer) {
    UPDK_OuterHeaderCreation *outerHeaderCreation = &(far->forwardingParameters.outerHeaderCreation);
    uint16_t outerHeaderLen = 0;
    uint16_t payloadLen = pkt->data_len;
    if (qer) {
        outerHeaderLen = sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) + sizeof(gtpv1_t) +
                 sizeof(gtpv1_hdr_opt_t) + sizeof(pdu_sess_container_hdr_t);
        payloadLen += sizeof(gtpv1_hdr_opt_t) + sizeof(pdu_sess_container_hdr_t);

    } else {
        outerHeaderLen = sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) + sizeof(gtpv1_t);
    }

    gtpv1_t *gtp_hdr = (gtpv1_t *)rte_pktmbuf_prepend(pkt, outerHeaderLen);
    gtp_hdr = rte_pktmbuf_mtod_offset(pkt, gtpv1_t *, sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr));
    gtpv1_set_header(gtp_hdr, payloadLen, outerHeaderCreation->teid);

    if (qer) {
        gtp_hdr->flags |= GTP1_F_EXTHDR;  // enable extension header
        gtpv1_hdr_opt_t *gtp_opt_hdr = rte_pktmbuf_mtod_offset(
            pkt, gtpv1_hdr_opt_t *, sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) + sizeof(gtpv1_t));
        gtp_opt_hdr->seq_number = 0;
        gtp_opt_hdr->NPDU = 0;
        gtp_opt_hdr->next_ehdr_type = GTPV1_NEXT_EXT_HDR_TYPE_85;

        pdu_sess_container_hdr_t *pdu_ss_ctr =
            rte_pktmbuf_mtod_offset(pkt, pdu_sess_container_hdr_t *,
                        sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) + sizeof(gtpv1_t) +
                        sizeof(gtpv1_hdr_opt_t));
        pdu_ss_ctr->length = 0x01;
        pdu_ss_ctr->pdu_sess_ctr = rte_cpu_to_be_16(QERGetQFI(qer));
        pdu_ss_ctr->next_hdr = 0x00;
    }

    struct rte_udp_hdr *udp_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_udp_hdr *, sizeof(struct rte_ipv4_hdr));
    onvm_pkt_fill_udp(udp_hdr, UDP_PORT_FOR_GTP, UDP_PORT_FOR_GTP,
              payloadLen + sizeof(gtpv1_t));  // pktdatalen-outerheaderlen=rawpacket_len, but here,
                              // udppayloadlen should be raw + gtp header

    struct rte_ipv4_hdr *ipv4_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *, 0);
    onvm_pkt_fill_ipv4(ipv4_hdr, rte_cpu_to_be_32(g_n3_ip_be), rte_cpu_to_be_32(outerHeaderCreation->ipv4.s_addr),
               IPPROTO_UDP);
    ipv4_hdr->total_length = rte_cpu_to_be_16(payloadLen + sizeof(gtpv1_t) + sizeof(struct rte_udp_hdr) +
                          sizeof(struct rte_ipv4_hdr));  // raw+gtp8+udp8+ip20
    ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);
}

static int
HandlePacketWithFar(struct rte_mbuf *pkt, UPDK_FAR *far, UPDK_QER *qer, 
                    uint16_t out_port, struct onvm_pkt_meta *meta) {
    int buff = 0;
#define FAR_ACTION_MASK 0x07
    if (far->flags.applyAction) {
        switch (far->applyAction & FAR_ACTION_MASK) {
            case UPDK_FAR_APPLY_ACTION_DROP:
                meta->action = ONVM_NF_ACTION_DROP;
                break;
            case UPDK_FAR_APPLY_ACTION_FORW:
                if (far->flags.forwardingParameters) {
                    if (far->forwardingParameters.flags.outerHeaderCreation) {
                        UPDK_OuterHeaderCreation *outerHeaderCreation =
                            &(far->forwardingParameters.outerHeaderCreation);
                        switch (outerHeaderCreation->description) {
                            case UPDK_OUTER_HEADER_CREATION_DESCRIPTION_GTPU_UDP_IPV4: {
                                Encap(pkt, far, qer);
                            } break;
                            case UPDK_OUTER_HEADER_CREATION_DESCRIPTION_GTPU_UDP_IPV6:
                            case UPDK_OUTER_HEADER_CREATION_DESCRIPTION_UDP_IPV4:
                            case UPDK_OUTER_HEADER_CREATION_DESCRIPTION_UDP_IPV6:
                            default:
                                UTLT_Error("Unknown outer header creation info");
                        }
                    }
                }
                // meta->destination = pkt->port ^ 1;
                meta->destination = out_port;
                meta->action = ONVM_NF_ACTION_OUT;
                break;
            case UPDK_FAR_APPLY_ACTION_BUFF:
                /* UL should never hit BUFF; DL uses per-session rings.
                 * If we get here unexpectedly, just drop the packet. */
                meta->action = ONVM_NF_ACTION_DROP;
                break;
            default:
                UTLT_Error("Unspec apply action[%u] in FAR[%u]", far->applyAction, far->farId);
        }
        // TODO(vivek): Complete these actions:
        if (far->applyAction & UPDK_FAR_APPLY_ACTION_NOCP) {
            // Send message to UPF-C
            Event *msg = (Event *)rte_calloc(NULL, 1, sizeof(Event), 0);
            msg->type = UPF_EVENT_SESSION_REPORT;
            msg->arg0 = seid;
            msg->arg1 = pdrId;
            /*
            struct ReportMsg *msg= (struct ReportMsg *) rte_calloc(NULL, 1, sizeof(struct ReportMsg), 0);
            msg->seid = seid;
            msg->pdrId = pdrId;
            */
            UTLT_Debug("Send to upf-c, namely service id is 2\n");
            onvm_nflib_send_msg_to_nf(2, msg);
        }
        if (far->applyAction & UPDK_FAR_APPLY_ACTION_DUPL) {
            UTLT_Error("Duplicate Apply action: %u not supported, dropping the packet", far->applyAction);
        }
    }
    return buff;
}

/* Per-session drain helper
 * Dequeue up to max_pkts from session ring, set meta OUT, and TX.
 * Returns the number of packets actually transmitted. */
static uint32_t
drain_session_batch(int sess_idx, uint32_t max_pkts, struct onvm_nf *nf) {
    UpfSessBuf *sb = &g_sess_buf[sess_idx];
    if (!sb->ring_created || !sb->ring)
        return 0;

    struct onvm_configuration *onvm_config = onvm_nflib_get_onvm_config();
    struct rte_mbuf *drain_buf[DRAIN_CHUNK];
    uint32_t total = 0;

    while (total < max_pkts) {
        uint32_t want = max_pkts - total;
        if (want > DRAIN_CHUNK) want = DRAIN_CHUNK;
        uint32_t n = rte_ring_sc_dequeue_burst(sb->ring,
                        (void **)drain_buf, want, NULL);
        if (n == 0) break;

        /* Restore action to OUT so onvm_pkt_process_tx_batch sends them */
        for (uint32_t j = 0; j < n; j++) {
            struct onvm_pkt_meta *m =
                onvm_get_pkt_meta(drain_buf[j],
                                  onvm_config->dynfield_offset);
            m->action = ONVM_NF_ACTION_OUT;
        }

        onvm_pkt_process_tx_batch(nf->nf_tx_mgr, drain_buf,
                                  onvm_config->dynfield_offset, n, nf);
        total += n;
    }
    if (total > 0)
        onvm_pkt_enqueue_tx_thread(nf->nf_tx_mgr->to_tx_buf, nf);
    if (rte_ring_count(sb->ring) == 0) {
        sb->touched = 0;
        sb->buffering_far_id = 0;
        __atomic_store_n(&sb->drain_far_id, 0, __ATOMIC_RELEASE);
    }
    __atomic_fetch_add(&g_sess_buffer_drained, total, __ATOMIC_RELAXED);
    return total;
}

/* Keep the packet behind the existing session backlog. The NF framework still
 * owns its original reference and will release it after packet_handler returns;
 * the ring owns the additional reference until a later drain callback. */
static int
enqueue_session_packet(UpfSessBuf *sb, struct rte_mbuf *pkt,
                       struct onvm_pkt_meta *meta, bool deferred_forw) {
    if (unlikely(sb == NULL || sb->ring == NULL || pkt == NULL || meta == NULL)) {
        if (meta != NULL)
            meta->action = ONVM_NF_ACTION_DROP;
        return -1;
    }

    rte_mbuf_refcnt_update(pkt, 1);
    if (rte_ring_sp_enqueue(sb->ring, pkt) != 0) {
        rte_mbuf_refcnt_update(pkt, -1);
        meta->action = ONVM_NF_ACTION_DROP;
        __atomic_fetch_add(&g_sess_buffer_full_drops, 1,
                           __ATOMIC_RELAXED);
        return -1;
    }

    sb->touched = 1;
    meta->action = ONVM_NF_ACTION_DROP;
    __atomic_fetch_add(&g_sess_buffer_queued, 1, __ATOMIC_RELAXED);
    if (deferred_forw) {
        __atomic_fetch_add(&g_sess_buffer_deferred_forw, 1,
                           __ATOMIC_RELAXED);
    }
    return 0;
}

/* Recover drain requests even if the notification message was lost, then
 * empty every locally active FIFO. Draining happens from the user callback,
 * after the framework has released the original references of packets that
 * were deferred by the current RX burst. */
static void
drain_ready_session_buffers(struct onvm_nf *nf) {
    for (uint32_t scanned = 0; scanned < SESS_DRAIN_SCAN_BUDGET; scanned++) {
        uint32_t sess_idx = g_sess_drain_scan_cursor++ % SESS_BUF_MAX_USERS;
        UpfSessBuf *sb = &g_sess_buf[sess_idx];

        if (__atomic_exchange_n(&sb->drain_requested, 0,
                                __ATOMIC_ACQ_REL) == 0)
            continue;
        uint32_t drain_far_id =
            __atomic_load_n(&sb->drain_far_id, __ATOMIC_ACQUIRE);
        if (sb->touched && sb->buffering_far_id != drain_far_id) {
            UTLT_Warning("Ignore session %u drain for FAR %u; FIFO belongs to FAR %u",
                         sess_idx, drain_far_id, sb->buffering_far_id);
            continue;
        }
        sb->is_buffering = 0;
        if (sb->touched)
            mark_session_drain_active((int)sess_idx);
    }

    for (uint32_t word_idx = 0; word_idx < SESS_DRAIN_BITMAP_WORDS;
         word_idx++) {
        uint64_t active = g_sess_drain_bitmap[word_idx];

        while (active != 0) {
            uint32_t bit_idx = (uint32_t)__builtin_ctzll(active);
            uint32_t sess_idx = word_idx * 64 + bit_idx;
            UpfSessBuf *sb;

            active &= active - 1;
            if (sess_idx >= SESS_BUF_MAX_USERS)
                continue;
            clear_session_drain_active((int)sess_idx);
            sb = &g_sess_buf[sess_idx];
            if (!sb->ring_created || !sb->ring || !sb->touched ||
                sb->is_buffering)
                continue;
            drain_session_batch((int)sess_idx, UINT32_MAX, nf);
            if (sb->touched && !sb->is_buffering)
                mark_session_drain_active((int)sess_idx);
        }
    }
}

static int
packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta, struct onvm_nf_local_ctx *nf_local_ctx) {
    /* Session backlog drains before newly queued shaper packets. Once a
     * session drain is active, defer inline shaper progress to the callback,
     * which runs the session drain first. */
    if (nf_local_ctx != NULL && nf_local_ctx->nf != NULL &&
        g_sess_drain_active_count == 0)
        drain_shaper_queues_budget(nf_local_ctx->nf,
                                   SHAPER_INLINE_DRAIN_BUDGET);
    if (pkt == NULL || meta == NULL) {
        return 0;
    }

    /* Get Ethernet header */
    struct rte_ether_hdr *eth = onvm_pkt_ether_hdr(pkt);
    if (!eth) {
        meta->action = ONVM_NF_ACTION_DROP;
        return 0;
    }

    /* Handle ARP packets */
    if (rte_be_to_cpu_16(eth->ether_type) == RTE_ETHER_TYPE_ARP) {
        handle_arp_packet(pkt, meta, nf_local_ctx);
        return 0;
    }

    /* Handle local ICMP echo request to UPF-U itself */
    if (handle_local_icmp_echo(pkt, meta, nf_local_ctx)) {
        return 0;
    }

    uint32_t cal_pktlen = 0;
    bool cal_pktlen_valid = false;
    UTLT_Trace("Get packet\n");
    UTLT_Info("Handle PKT from port: %d [len: %d]", pkt->port, pkt->pkt_len);

    bool is_dl = false;
    meta->action = ONVM_NF_ACTION_DROP;

    /* Get IPv4 header */
    struct rte_ipv4_hdr *iph = onvm_pkt_ipv4_hdr(pkt);
    if (iph == NULL) {
        UTLT_Info("Not IP packet, ignore it\n");
        return 0;
    }
    cal_pktlen_valid = dl_qos_packet_len(pkt, iph, &cal_pktlen);

    // Flip to a newly published snapshot if a REQ was received
    UpfClsMaybeFlipAndAck();

    UPDK_PDR *pdr = NULL;
    gtp_parse_result_t gtp_info = {0};
    int ue_idx = -1;
    UpfSession *owner_session = NULL;
    uint32_t ue_key = 0;
    struct shaper_flow_key dl_flow_key = {0};

    /* char *src_address = convertToIpAddressString(iph->src_addr);
    UTLT_Info("Src IP is %s\n", src_address);
    char *dst_address = convertToIpAddressString(iph->dst_addr);
    UTLT_Info("Dst IP is %s\n", dst_address); */

    if (iph->dst_addr == g_n3_ip_be) {  //
        UTLT_Info("It is uplink\n");

        struct rte_udp_hdr *udp_header = onvm_pkt_udp_hdr(pkt);
        if (udp_header == NULL) {
            return 0;
        }

        if (parse_gtpu_once(pkt, &gtp_info) < 0 || !gtp_info.valid) {
            return 0;
        }
        pdr = GetPdrByTeid(pkt, &gtp_info);

    } else {
        // UTLT_Info("It is downlink, dst is %s\n", convertToIpAddressString(iph->dst_addr));
        pdr = GetPdrByUeIpAddress(pkt, rte_cpu_to_be_32(iph->dst_addr));
        is_dl = true;
    }

    if (!pdr) {
        UTLT_Error("no PDR found for %s, skip\n", convertToIpAddressString(iph->dst_addr));
        meta->action = ONVM_NF_ACTION_DROP;
        return 0;
    }
    UTLT_Info("Got PDR ID is %u\n", pdr->pdrId);

    if (is_dl) {
        ue_key = rte_cpu_to_be_32(iph->dst_addr);
        if (!cal_pktlen_valid) {
            UTLT_Warning("Invalid DL IPv4/L4 length for UE %s, drop",
                         convertToIpAddressString(iph->dst_addr));
            meta->action = ONVM_NF_ACTION_DROP;
            return 0;
        }
        owner_session = UpfSessionFindByUeIP(ue_key);
        ue_idx = findIndexByUeIpAddress(ue_key);
        if (ue_idx < 0) {
            ue_idx = GetQerByUEIpAddressFromPdr(ue_key, owner_session, pdr,
                                                convertToIpAddressString(iph->dst_addr));
        }
        if (!build_dl_shaper_flow_key(pkt, pdr, ue_key, pdr->has_fd,
                                      &dl_flow_key)) {
            UTLT_Error("Failed to build DL shaper flow key");
            meta->action = ONVM_NF_ACTION_DROP;
            return 0;
        }
    }

    rte_pktmbuf_adj(pkt, sizeof(struct rte_ether_hdr));

    UPDK_FAR *far;
    far = pdr->far;
    if (!far) {
        UTLT_Error("There is no FAR related to PDR[%u]\n", pdr->pdrId);
        meta->action = ONVM_NF_ACTION_DROP;
        return 0;
    }

    if (pdr->flags.outerHeaderRemoval) {
        switch (pdr->outerHeaderRemoval) {
            case OUTER_HEADER_REMOVAL_GTP_IP4: {
                rte_pktmbuf_adj(pkt, gtp_info.outer_hdr_len);
            } break;
            case OUTER_HEADER_REMOVAL_GTP_IP6:
            case OUTER_HEADER_REMOVAL_UDP_IP4:
            case OUTER_HEADER_REMOVAL_UDP_IP6:
            case OUTER_HEADER_REMOVAL_IP4:
            case OUTER_HEADER_REMOVAL_IP6:
            case OUTER_HEADER_REMOVAL_GTP:
            case OUTER_HEADER_REMOVAL_S_TAG:
            case OUTER_HEADER_REMOVAL_S_C_TAG:
            default:
                printf("unknown or not implement\n");
        }
    }

    if (is_dl) {
        /* ── DL: split BUFF vs FORW ─────────────────────────── */
        uint8_t far_action = far->applyAction & FAR_ACTION_MASK;
        int32_t sess_idx = pdr->session_index;
        bool defer_for_order = false;

        /* DROP → just let the framework free the pkt */
        if (far_action == UPDK_FAR_APPLY_ACTION_DROP) {
            meta->action = ONVM_NF_ACTION_DROP;
            goto dl_nocp;
        }
         /* Validate session ring */
        if (sess_idx < 0 || sess_idx >= SESS_BUF_MAX_USERS) {
            meta->action = ONVM_NF_ACTION_DROP;
            goto dl_nocp;
        }
        UpfSessBuf *sb = &g_sess_buf[sess_idx];
        if (!sb->ring_created || !sb->ring) {
            meta->action = ONVM_NF_ACTION_DROP;
            goto dl_nocp;
        }

        /* Encap (GTP-U outer header) */
        if (far->flags.forwardingParameters &&
            far->forwardingParameters.flags.outerHeaderCreation) {
            UPDK_OuterHeaderCreation *ohc =
                &far->forwardingParameters.outerHeaderCreation;
            if (ohc->description ==
                UPDK_OUTER_HEADER_CREATION_DESCRIPTION_GTPU_UDP_IPV4)
                Encap(pkt, far, pdr->qer);
        }

        /* Get the gNB N3 IP address */
        uint32_t gnb_n3_ip_be =
            far->forwardingParameters.outerHeaderCreation.ipv4.s_addr;
        UTLT_Trace("gNB N3 IP: %s\n", convertToIpAddressString(gnb_n3_ip_be));

        // Regardless of BUFF vs FORW, we need to attach L2 (or ARP) header
        // before sending to N3 port.
        if (attach_l2_or_arp(pkt, g_n3_port, g_n3_ip_be, gnb_n3_ip_be,
                            nf_local_ctx->nf) < 0) {
            meta->action = ONVM_NF_ACTION_DROP;   /* or buffer */
            return 0;
        }
        meta->destination = g_n3_port; // DL always goes to N3 port after FAR processing (may be modified by QoS policing below)

        if (far_action == UPDK_FAR_APPLY_ACTION_BUFF) {
            /* Buffer-only: prepare packet for later TX, enqueue, then DROP */
            if (sb->touched && sb->buffering_far_id != far->farId) {
                meta->action = ONVM_NF_ACTION_DROP;
                __atomic_fetch_add(&g_sess_buffer_far_conflict_drops, 1,
                                   __ATOMIC_RELAXED);
                goto dl_nocp;
            }
            if (!sb->touched)
                sb->buffering_far_id = far->farId;
            sb->is_buffering = 1;
            if (enqueue_session_packet(sb, pkt, meta, false) < 0 &&
                !sb->touched)
                sb->buffering_far_id = 0;
            goto dl_nocp;
        }

        /* A FORW packet must not overtake packets already buffered for this
         * FAR. Schedule the old FIFO first, but let the current packet pass
         * through normal QoS handling before deciding where it waits. */
        if (far_action == UPDK_FAR_APPLY_ACTION_FORW && sb->touched &&
            sb->buffering_far_id == far->farId) {
            sb->is_buffering = 0;
            mark_session_drain_active(sess_idx);
            defer_for_order = true;
        }

        /* QoS shaping — FORW only, after GTP-U/L2 TX prep is complete.
         * Over-token packets wait in bounded per-flow FIFOs; only red,
         * invalid, or queue-overflow packets drop. */
        if (far_action == UPDK_FAR_APPLY_ACTION_FORW) {
            if (ue_idx < 0) {
                UTLT_Error("No UE IP found in the table");
                meta->action = ONVM_NF_ACTION_DROP;
                goto dl_nocp;
            }

            int color_result = 0;
            bool isQos = false;
            uint64_t curr_time = rte_get_tsc_cycles();

            if (pdr->has_fd) {
                isQos = true;
                int ft_idx = ftSearch(pdr->meter_key);
                struct rte_meter_trtcm_profile *trtcm_profile;
                if (unlikely(ft_idx < 0 || ft_idx >= (int)APP_FLOWS_MAX)) {
                    UTLT_Warning("DL QoS: no trTCM flow for meter_key=%u (ft_idx=%d) pdr=%u seid=%lu; dropping",
                                 pdr->meter_key, ft_idx, pdr->pdrId, seid);
                    meta->flags = RTE_COLOR_RED;
                    meta->action = ONVM_NF_ACTION_DROP;
                    goto dl_nocp;
                }
                trtcm_profile = trtcmProfileForFlow(ft_idx);
                if (unlikely(trtcm_profile == NULL)) {
                    UTLT_Warning("DL QoS: no trTCM profile for meter_key=%u ft_idx=%d pdr=%u seid=%lu; dropping",
                                 pdr->meter_key, ft_idx, pdr->pdrId, seid);
                    meta->flags = RTE_COLOR_RED;
                    meta->action = ONVM_NF_ACTION_DROP;
                    goto dl_nocp;
                }
                color_result = trtcmColorHandle(cal_pktlen, curr_time,
                                                ft_idx, trtcm_profile);
                if (unlikely(color_result < 0)) {
                    meta->flags = RTE_COLOR_RED;
                    meta->action = ONVM_NF_ACTION_DROP;
                    goto dl_nocp;
                }
                // set the meta action to out for now, and trtcmPolicer will update it to drop if color is red
                meta->action = ONVM_NF_ACTION_OUT;
                if (trtcmPolicer(meta, color_result) > 0)
                    UTLT_Error("trTCM Policer error");
            }

            if (isQos) {
                if (meta->flags == RTE_COLOR_RED) {
                    meta->action = ONVM_NF_ACTION_DROP;
                    __atomic_fetch_add(&g_shaper_drop_red, 1, __ATOMIC_RELAXED);
                    goto dl_nocp;
                }
                if (meta->flags == RTE_COLOR_GREEN ||
                    meta->flags == RTE_COLOR_YELLOW) {
                    enum shaper_pkt_color color =
                        (meta->flags == RTE_COLOR_GREEN) ?
                        SHAPER_COLOR_GREEN : SHAPER_COLOR_YELLOW;
                    enum shaper_decision decision =
                        shape_or_enqueue_packet(ue_idx, &dl_flow_key, true,
                                                color, pkt, cal_pktlen, meta);
                    if (decision != SHAPER_PASS)
                        goto dl_nocp;
                }
            } else {
                enum shaper_decision decision =
                    shape_or_enqueue_packet(ue_idx, &dl_flow_key, false,
                                            SHAPER_COLOR_NQOS, pkt,
                                            cal_pktlen, meta);
                if (decision != SHAPER_PASS)
                    goto dl_nocp;
            }
        }

        /* If normal QoS permits immediate transmission, put this packet behind
         * the old session backlog. Packets queued or dropped by QoS have
         * already left through dl_nocp above; the old FIFO still drains first
         * from the callback. */
        if (defer_for_order) {
            enqueue_session_packet(sb, pkt, meta, true);
            goto dl_nocp;
        }

        /* No matching session backlog remains, so the current packet can be
         * forwarded directly after the normal QoS checks above. */
        if (!sb->touched)
            sb->is_buffering = 0;
        meta->action = ONVM_NF_ACTION_OUT;

        goto dl_nocp;

    dl_nocp:
        if (far->applyAction & UPDK_FAR_APPLY_ACTION_NOCP) {
            Event *msg = (Event *)rte_calloc(NULL, 1, sizeof(Event), 0);
            msg->type = UPF_EVENT_SESSION_REPORT;
            msg->arg0 = seid;
            msg->arg1 = pdrId;
            UTLT_Debug("Send to upf-c, namely service id is 2\n");
            onvm_nflib_send_msg_to_nf(2, msg);
        } 
        return 0;
    } else {
        /* ── UL: original HandlePacketWithFar path (unchanged) ── */
        int status = HandlePacketWithFar(pkt, far, pdr->qer, g_n6_port, meta);

        /* Get Inner IPv4 header */
        struct rte_ipv4_hdr *inner_iph = rte_pktmbuf_mtod(pkt, struct rte_ipv4_hdr *);
        if (inner_iph == NULL) {
            UTLT_Warning("Inner packet is NULL, drop it\n");
            meta->action = ONVM_NF_ACTION_DROP;
            return 0;
        }

        if ((inner_iph->version_ihl >> 4) != 4) {
            UTLT_Warning("Inner packet is not IPv4, drop it\n");
            meta->action = ONVM_NF_ACTION_DROP;
            return 0;
        }

        if (meta->action == ONVM_NF_ACTION_OUT) {
            /* Get the DN server IP address */
            uint32_t dn_server_ip_be = inner_iph->dst_addr;
            UTLT_Trace("DN server IP: %s\n", convertToIpAddressString(dn_server_ip_be));

            /* UL QoS policing (flow-level): applies when CP provided SDF (has_fd)
             * and per-flow QER contains MBR/GBR. For UDP tests, you must check
             * server-side throughput/loss or use TCP to observe the cap. */
            if (pdr && pdr->has_fd && pdr->qer && pdr->qer->flags.maximumBitrate) {
                uint32_t dst_ip_host = rte_be_to_cpu_32(dn_server_ip_be);
                if (!pdr->has_fd_to || (dst_ip_host & pdr->fd_to_mask) == pdr->fd_to_net) {
                    int ft_idx = ftSearch(pdr->meter_key);
                    if (unlikely(ft_idx < 0 || ft_idx >= (int)APP_FLOWS_MAX)) {
                        UTLT_Warning("UL QoS: no trTCM flow for meter_key=%u (ft_idx=%d) pdr=%u seid=%lu; dropping",
                                    pdr->meter_key, ft_idx, pdr->pdrId, seid);
                        meta->flags = RTE_COLOR_RED;
                        meta->action = ONVM_NF_ACTION_DROP;
                        return 0;
                    }

                    uint64_t curr_time = rte_get_tsc_cycles();
                    struct rte_meter_trtcm_profile *trtcm_profile =
                        trtcmProfileForFlow(ft_idx);
                    if (unlikely(trtcm_profile == NULL)) {
                        UTLT_Warning("UL QoS: no trTCM profile for meter_key=%u ft_idx=%d pdr=%u seid=%lu; dropping",
                                    pdr->meter_key, ft_idx, pdr->pdrId, seid);
                        meta->flags = RTE_COLOR_RED;
                        meta->action = ONVM_NF_ACTION_DROP;
                        return 0;
                    }
                    int color_result = trtcmColorHandle(pkt->pkt_len, curr_time,
                                                        ft_idx, trtcm_profile);
                    if (unlikely(color_result < 0)) {
                        meta->flags = RTE_COLOR_RED;
                        meta->action = ONVM_NF_ACTION_DROP;
                        return 0;
                    }
                    if (trtcmPolicer(meta, color_result) > 0)
                        UTLT_Error("UL trTCM Policer error");

                    if (meta->action == ONVM_NF_ACTION_DROP)
                        return 0;
                }
            }

            /* Attach L2 (or ARP) header for the N6-bound packet */
            if (attach_l2_or_arp(pkt, g_n6_port, g_n6_ip_be, dn_server_ip_be,
                                nf_local_ctx->nf) < 0) {
                meta->action = ONVM_NF_ACTION_DROP;
                return 0;
            }
        }
        return status;
    }
}

void
msg_handler(void *msg_data, struct onvm_nf_local_ctx *nf_local_ctx) {

    Event *e = (Event *)msg_data;

    /* Our NF→NF control path: CP tells us to flip */
    if (e && (uint32_t)e->type == EVT_CLS_GC_REQ) {
        g_cls_local.pending_ver = (uint32_t)e->arg0;
        g_cls_local.flip_pending = 1;      // The actual flip happens at burst boundary

        // logging block

        UTLT_Info("EVT_CLS_GC_REQ: requested_ver=%u ctrl.active=%p ctrl.ver=%u",
          (uint32_t)e->arg0,
          (void*)(g_upf_cls_ctrl ? g_upf_cls_ctrl->active : NULL),
          (g_upf_cls_ctrl ? g_upf_cls_ctrl->version : 0));

        rte_free(e);
        return;
    }

    /* EVENT drain: CP tells us BUFF→FORW for a specific session */
    if (e && (uint32_t)e->type == UPF_EVENT_CLEAR_AND_DRAIN) {
        struct onvm_nf *nf = nf_local_ctx->nf;
        int sess_idx = (int)(uintptr_t)e->arg0;
        if (sess_idx >= 0 && sess_idx < SESS_BUF_MAX_USERS) {
            UpfSessBuf *sb = &g_sess_buf[sess_idx];
            uint8_t requested =
                __atomic_exchange_n(&sb->drain_requested, 0,
                                    __ATOMIC_ACQ_REL);

            if (!requested) {
                UTLT_Debug("Ignore stale session drain event: sess %d\n",
                           sess_idx);
            } else {
                uint32_t drain_far_id =
                    __atomic_load_n(&sb->drain_far_id, __ATOMIC_ACQUIRE);

                if (!sb->touched || sb->buffering_far_id == drain_far_id) {
                    sb->is_buffering = 0;
                    uint32_t n =
                        drain_session_batch(sess_idx, UINT32_MAX, nf);
                    clear_session_drain_active(sess_idx);
                    UTLT_Debug("EVENT drain: sess %d FAR %u, sent %u pkts\n",
                               sess_idx, drain_far_id, n);
                } else {
                    UTLT_Warning("Ignore session %d drain for FAR %u; FIFO belongs to FAR %u",
                                 sess_idx, drain_far_id,
                                 sb->buffering_far_id);
                }
            }
        }
        rte_free(e);
        return;
    }

    if (e) rte_free(e);
}

static uint64_t last_p = 0;

static int
callback_handler(struct onvm_nf_local_ctx *nf_local_ctx) {
    struct onvm_nf *nf;
    uint64_t cur_p;

    if (unlikely(nf_local_ctx == NULL || nf_local_ctx->nf == NULL))
        return 0;

    nf = nf_local_ctx->nf;
    if (unlikely(!last_p)) last_p = rte_get_tsc_cycles();
    cur_p = rte_get_tsc_cycles();

    drain_ready_session_buffers(nf);
    drain_shaper_queues(nf);

    if (unlikely(cur_p - last_p > rte_get_timer_hz())) {
        last_p = cur_p;
        UTLT_Debug("Stats perform: ");
        UTLT_Debug("act out: %d", nf->stats.act_out);
        UTLT_Debug("buffered: %d", nf->stats.tx_buffer);
        UTLT_Debug("session buffer queued: %" PRIu64,
                   __atomic_load_n(&g_sess_buffer_queued, __ATOMIC_RELAXED));
        UTLT_Debug("session buffer drained: %" PRIu64,
                   __atomic_load_n(&g_sess_buffer_drained, __ATOMIC_RELAXED));
        UTLT_Debug("session buffer full drops: %" PRIu64,
                   __atomic_load_n(&g_sess_buffer_full_drops, __ATOMIC_RELAXED));
        UTLT_Debug("session buffer deferred FORW: %" PRIu64,
                   __atomic_load_n(&g_sess_buffer_deferred_forw,
                                   __ATOMIC_RELAXED));
        UTLT_Debug("session buffer FAR-conflict drops: %" PRIu64,
                   __atomic_load_n(&g_sess_buffer_far_conflict_drops,
                                   __ATOMIC_RELAXED));
        UTLT_Debug("shaper queued: %" PRIu64,
                   __atomic_load_n(&g_shaper_queued, __ATOMIC_RELAXED));
        UTLT_Debug("shaper drained: %" PRIu64,
                   __atomic_load_n(&g_shaper_drained, __ATOMIC_RELAXED));
        UTLT_Debug("shaper invalid drops: %" PRIu64,
                   __atomic_load_n(&g_shaper_drop_invalid, __ATOMIC_RELAXED));
        UTLT_Debug("shaper red drops: %" PRIu64,
                   __atomic_load_n(&g_shaper_drop_red, __ATOMIC_RELAXED));
        UTLT_Debug("shaper green overflow drops: %" PRIu64,
                   __atomic_load_n(&g_shaper_drop_green_overflow, __ATOMIC_RELAXED));
        UTLT_Debug("shaper yellow overflow drops: %" PRIu64,
                   __atomic_load_n(&g_shaper_drop_yellow_overflow, __ATOMIC_RELAXED));
        UTLT_Debug("shaper non-QoS overflow drops: %" PRIu64,
                   __atomic_load_n(&g_shaper_drop_nqos_overflow, __ATOMIC_RELAXED));
        UTLT_Debug("shaper flow table full drops: %" PRIu64,
                   __atomic_load_n(&g_shaper_drop_flow_table_full, __ATOMIC_RELAXED));
        UTLT_Debug("shaper flow queue full drops: %" PRIu64,
                   __atomic_load_n(&g_shaper_drop_flow_queue_full, __ATOMIC_RELAXED));
        UTLT_Debug("shaper UE queue full drops: %" PRIu64,
                   __atomic_load_n(&g_shaper_drop_ue_queue_full, __ATOMIC_RELAXED));
        UTLT_Debug("shaper mempool empty drops: %" PRIu64,
                   __atomic_load_n(&g_shaper_drop_mempool_empty, __ATOMIC_RELAXED));
    }

    return 0;
}

int
main(int argc, char *argv[]) {
    int arg_offset;
    struct onvm_nf_local_ctx *nf_local_ctx;
    struct onvm_nf_function_table *nf_function_table;
    UTLT_SetLogLevel("warning"); // temporary default before config is loaded

    nf_local_ctx = onvm_nflib_init_nf_local_ctx();
    onvm_nflib_start_signal_handler(nf_local_ctx, NULL);
    nf_function_table = onvm_nflib_init_nf_function_table();
    nf_function_table->pkt_handler = &packet_handler;
    nf_function_table->msg_handler = &msg_handler;
    nf_function_table->user_actions = &callback_handler;

    if ((arg_offset = onvm_nflib_init(argc, argv, NF_TAG, nf_local_ctx, nf_function_table)) < 0) {
        onvm_nflib_stop(nf_local_ctx);
        if (arg_offset == ONVM_SIGNAL_TERMINATION) {
            printf("Exiting due to user termination\n");
            return 0;
        } else {
            rte_exit(EXIT_FAILURE, "Failed ONVM init\n");
        }
    }

    /* Initialize dynamic field offset */
    struct onvm_configuration *onvm_config = onvm_nflib_get_onvm_config();
    nf_local_ctx->nf->dynfield_offset = onvm_config->dynfield_offset;

    const char *config_path = "config/upf_u.yaml";

    if (argc > arg_offset + 1) {
        config_path = argv[arg_offset + 1];
    }

    printf("[UPF-U] Using config: %s\n", config_path);
    if (UpfU_LoadAndParseConfig(config_path) != 0) {
        rte_exit(EXIT_FAILURE, "Failed to load/parse UPF-U YAML config.\n");
    }

    UTLT_SetLogLevel(g_log_level);
    printf("[UPF-U] Log level: %s\n", g_log_level);

    if (UpfClsCtrlInit() < 0) {
        rte_exit(EXIT_FAILURE, "CLS_CTRL memzone init failed\n");
    }

    if (UpfSessBufInit() < 0) {
        rte_exit(EXIT_FAILURE, "SESS_BUF memzone init failed\n");
    }

    // Initialize L2 addresses, must be done after config is loaded (UpfU_LoadAndParseConfig)
    init_l2_addrs();

    // trTCM
    trtcmConfigFlowTables();
    initUeTable();
    ueHashInit();

    UpfSessionPoolInit();
    UeIpToUpfSessionMapInit();
    TeidToUpfSessionMapInit();

    /* ARP module init */
    if (upf_arp_init() < 0) {
        rte_exit(EXIT_FAILURE, "failed to init ARP module\n");
    }

    shaper_init_state();
    if (shaper_init_entry_pool(nf_local_ctx->nf) < 0) {
        rte_exit(EXIT_FAILURE, "Failed to init UPF-U shaper entry pool.\n");
    }

    onvm_nflib_run(nf_local_ctx);

    shaper_cleanup();
    onvm_nflib_stop(nf_local_ctx);
    return 0;
}
