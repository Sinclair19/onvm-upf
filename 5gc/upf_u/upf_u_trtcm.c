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

#include "upf_context.h"
#include "upf_u_trtcm.h"
#include "utlt_debug.h"
#include "upf_u_config.h"

#include <inttypes.h>
#include <stdint.h>
#include <string.h>

#include <rte_spinlock.h>

#include "../classifiers/classifier_wrapper.h"

#define MIN_TOKEN_BUCKET_DEPTH 2048
#define TOKEN_BUCKET_BURST_MS 100
#define TRTCM_BURST_MS 100

flow_entry_t iPFlows[APP_FLOWS_MAX];
uint32_t iPFlowsLen = 0;
uint32_t trTCMidx = 0;

struct rte_meter_trtcm_profile app_trtcm_profile;
struct rte_meter_trtcm_profile app_flow_trtcm_profiles[APP_FLOWS_MAX];
struct rte_meter_trtcm app_flows[APP_FLOWS_MAX];
static bool app_flow_has_gbr[APP_FLOWS_MAX];

static struct ue_hash_entry ue_hash[MAX_UE];
struct ue_tb ue_table[MAX_UE];
static rte_spinlock_t ue_table_lock;
static rte_spinlock_t ue_tb_locks[MAX_UE];

/* trTCM */
struct rte_meter_trtcm_params app_trtcm_params = {
	.cir = 125000,    // bytes per secs
	.pir = 625000,    // bytes per secs
	.cbs = 2048,
	.pbs = 2048
};

int
trtcmConfigFlowTables(void) {
    uint32_t i;
    int rtn;
    if (likely(app_flows[0].tc > 0))
        return 0;

    // config trtcm profile
    rtn = rte_meter_trtcm_profile_config(&app_trtcm_profile,
		&app_trtcm_params);
	if (rtn)
		return rtn;

    // config flow meters with trtcm profiles
    for (i = 0; i < APP_FLOWS_MAX; i++){
        app_flow_trtcm_profiles[i] = app_trtcm_profile;
        app_flow_has_gbr[i] = true;
        rtn = rte_meter_trtcm_config(&app_flows[i],
                                     &app_flow_trtcm_profiles[i]);
        if (rtn)
            return rtn;
    }

    UTLT_Info("Flow table configured.");
    return 0;
}

int
trtcmColorHandle(uint32_t pkt_len, uint64_t time, int flow_idx, struct rte_meter_trtcm_profile *target_profile) {
    uint8_t out_color = 0;
    // check configured flow
    if (unlikely(flow_idx < 0 || flow_idx >= (int)APP_FLOWS_MAX ||
                 target_profile == NULL)) {
        UTLT_Info("flow index/profile set err");
        return -1;
    }
    if (unlikely(target_profile->cir_period == 0)) {
        UTLT_Info("flow cir_period set err");
        return -1;
    }
    if (unlikely(target_profile->pir_period == 0)) {
        UTLT_Info("flow pir_period set err");
        return -1;
    }
    out_color = (uint8_t) rte_meter_trtcm_color_blind_check(&app_flows[flow_idx],
        target_profile,
        time,
        pkt_len);
    if (!app_flow_has_gbr[flow_idx] && out_color == RTE_COLOR_GREEN)
        out_color = RTE_COLOR_YELLOW;
    return out_color;
}

struct rte_meter_trtcm_profile *
trtcmProfileForFlow(int flow_idx) {
    if (unlikely(flow_idx < 0 || flow_idx >= (int)APP_FLOWS_MAX))
        return NULL;

    return &app_flow_trtcm_profiles[flow_idx];
}

int
trtcmPolicer(struct onvm_pkt_meta *meta, int color_result) {
    if (meta->action == ONVM_NF_ACTION_DROP) {
        meta->flags = RTE_COLOR_RED;
        UTLT_Info("TB not enough & traffic flow");
        return 0;
    }
    switch (color_result) {
        case RTE_COLOR_RED:
            UTLT_Info("\033[0;31mRED(%d)\033[0m, drop pkt", RTE_COLOR_RED);
            meta->flags = RTE_COLOR_RED;
            meta->action = ONVM_NF_ACTION_DROP;
            break;
        case RTE_COLOR_YELLOW:
            UTLT_Info("\033[0;32mYELLOW(%d)\033[0m, best effort pkt fwd", RTE_COLOR_YELLOW);
            meta->flags = RTE_COLOR_YELLOW;
	        meta->action = ONVM_NF_ACTION_OUT;
            break;
        case RTE_COLOR_GREEN:
            UTLT_Info("\033[0;33mGREEEN(%d)\033[0m, guaranted pkt fwd.", RTE_COLOR_GREEN);
            meta->flags = RTE_COLOR_GREEN;
            meta->action = ONVM_NF_ACTION_OUT;
            break;
        default:
            UTLT_Error("Unexpected trTCM color output.");
            return 1;
    }
    return 0;
}

// static inline source_interface_t
// PortToSourceInterface(uint16_t port) {
//     if (port == g_n3_port)  return SRC_IF_ACCESS;
//     if (port == g_n6_port)    return SRC_IF_CORE;
//     if (port == g_sgi_port)     return SRC_IF_SGI_LAN;
//     UTLT_Warning("PortToSourceInterface: unknown port %" PRIu16
//              " (N3=%" PRIu16 " N6=%" PRIu16 " SGI=%" PRIu16
//              ") — defaulting to ACCESS",
//              port, g_n3_port, g_n6_port, g_sgi_port);

//     return SRC_IF_ACCESS;
// }

static inline uint16_t
SourceInterfaceToPort(source_interface_t srcIf) {
    switch (srcIf) {
      case SRC_IF_ACCESS:   return g_n3_port;
      case SRC_IF_CORE:     return g_n6_port;
      case SRC_IF_SGI_LAN:  return g_sgi_port;
      case SRC_IF_CP_FUNC:
      case SRC_IF_LI_FUNC:
      default:
        return -1; // Invalid/unsupported source interface
    }
}

static inline int
hashFunc(uint32_t subnet) {
    return subnet % APP_FLOWS_MAX;
}

int
ftSearch(uint32_t subnet) {
    int index = hashFunc(subnet);
    int original_index = index;

    while (iPFlows[index].in_use) {
        if (iPFlows[index].subnet == subnet) {
            return iPFlows[index].flow_idx;
        }
        index = (index + 1) % APP_FLOWS_MAX;  // Linear Probing

        if (index == original_index) {
            break;
        }
    }

    return -1;  // Not found
}

static inline bool
ftAddEntry(uint32_t subnet, int flow_idx) {
    if (iPFlowsLen >= APP_FLOWS_MAX) {
        printf("Error: Maximum flow entries reached.\n");
        return false;
    }

    if (ftSearch(subnet) != -1) {
        printf("Error: Subnet %u already exists.\n", subnet);
        return false;
    }

    int index = hashFunc(subnet);
    while (iPFlows[index].in_use) {         // Linear Probing
        index = (index + 1) % APP_FLOWS_MAX;
    }

    // Insert the entry
    iPFlows[index].subnet = subnet;
    iPFlows[index].flow_idx = flow_idx;
    iPFlows[index].in_use = true;
    iPFlowsLen++;

    return true;
}

void
initUeTable() {
    rte_spinlock_init(&ue_table_lock);
    for (int i = 0; i < MAX_UE; i++) {
        uint64_t now = rte_get_tsc_cycles();

        rte_spinlock_init(&ue_tb_locks[i]);
        memset(&ue_table[i], 0, sizeof(ue_table[i]));
        ue_table[i].session_ambr_tb.last_cycle = now;
        ue_table[i].session_ambr_tb.cur_cycles = now;
        for (int qer_idx = 0; qer_idx < SHAPER_MAX_GBR_QERS_PER_UE;
             qer_idx++) {
            ue_table[i].gbr_qers[qer_idx].gfbr_tb.last_cycle = now;
            ue_table[i].gbr_qers[qer_idx].gfbr_tb.cur_cycles = now;
            ue_table[i].gbr_qers[qer_idx].mfbr_tb.last_cycle = now;
            ue_table[i].gbr_qers[qer_idx].mfbr_tb.cur_cycles = now;
        }
    }
}

static inline int
ueHashFunc(uint32_t ip) { return ip % MAX_UE; }

static inline bool
ueHashSlotInUse(int idx) {
    return __atomic_load_n(&ue_hash[idx].in_use, __ATOMIC_ACQUIRE);
}

static inline void
ueHashSetInUse(int idx, bool in_use) {
    __atomic_store_n(&ue_hash[idx].in_use, in_use, __ATOMIC_RELEASE);
}

static inline uint64_t
shaper_bucket_depth(uint64_t rate_kbps) {
    __uint128_t depth_bytes;

    if (rate_kbps == 0)
        return 0;

    depth_bytes = ((__uint128_t)rate_kbps * TOKEN_BUCKET_BURST_MS + 7) / 8;
    if (depth_bytes < MIN_TOKEN_BUCKET_DEPTH)
        return MIN_TOKEN_BUCKET_DEPTH;
    return depth_bytes > UINT64_MAX ? UINT64_MAX : (uint64_t)depth_bytes;
}

static inline uint64_t
trtcm_bucket_depth(uint64_t rate_kbps) {
    __uint128_t depth_bytes;

    if (rate_kbps == 0)
        return MIN_TOKEN_BUCKET_DEPTH;

    depth_bytes = ((__uint128_t)rate_kbps * TRTCM_BURST_MS + 7) / 8;
    if (depth_bytes < MIN_TOKEN_BUCKET_DEPTH)
        return MIN_TOKEN_BUCKET_DEPTH;
    return depth_bytes > UINT64_MAX ? UINT64_MAX : (uint64_t)depth_bytes;
}

static inline void
shaper_update_bucket_tokens(struct tb_config *tb, uint64_t cur_cycles) {
    uint64_t elapsed_cycles;
    uint64_t cycles_used;
    uint64_t tsc_hz;
    uint64_t tokens_produced;
    __uint128_t byte_rate;
    __uint128_t produced;

    if (tb->tb_rate == 0 || tb->tb_depth == 0) {
        tb->tb_tokens = 0;
        tb->last_cycle = cur_cycles;
        return;
    }

    if (tb->tb_tokens >= tb->tb_depth) {
        tb->tb_tokens = tb->tb_depth;
        tb->last_cycle = cur_cycles;
        return;
    }

    elapsed_cycles = cur_cycles - tb->last_cycle;
    tsc_hz = rte_get_tsc_hz();
    byte_rate = (__uint128_t)tb->tb_rate * 125;
    produced = ((__uint128_t)elapsed_cycles * byte_rate) / tsc_hz;
    tokens_produced = produced > UINT64_MAX ? UINT64_MAX :
                      (uint64_t)produced;
    if (tokens_produced == 0)
        return;

    if (tokens_produced >= tb->tb_depth - tb->tb_tokens) {
        tb->tb_tokens = tb->tb_depth;
        tb->last_cycle = cur_cycles;
        return;
    }

    tb->tb_tokens += tokens_produced;
    cycles_used = (uint64_t)(((__uint128_t)tokens_produced * tsc_hz) /
                             byte_rate);
    if (cycles_used == 0)
        cycles_used = 1;
    tb->last_cycle += cycles_used;
}

static inline bool
ueTokenIndexValid(int index) {
    return index > -1 && index < MAX_UE && ue_table[index].ue_ip != 0;
}

static inline void
initBucket(struct tb_config *tb, uint64_t rate, uint64_t now) {
    tb->tb_rate = rate;
    tb->tb_depth = shaper_bucket_depth(rate);
    tb->tb_tokens = tb->tb_depth;
    tb->last_cycle = now;
    tb->cur_cycles = now;
}

static inline bool
bucketCanFitPacket(const struct tb_config *tb, uint32_t pkt_len) {
    return tb->tb_depth > 0 && pkt_len <= tb->tb_depth;
}

static inline struct gbr_qer_tb *
findGbrQerLocked(int index, uint32_t qer_id) {
    for (int qer_idx = 0; qer_idx < SHAPER_MAX_GBR_QERS_PER_UE; qer_idx++) {
        struct gbr_qer_tb *qer = &ue_table[index].gbr_qers[qer_idx];

        if (qer->used && qer->qer_id == qer_id)
            return qer;
    }
    return NULL;
}

void
ueHashInit(void) {
    for (int i = 0; i < MAX_UE; i++)
        ueHashSetInUse(i, false);
}

void
ConfigureQerFlows(const UPDK_PDR *pdr, bool is_uplink) {
    /* pdr->qer is the QFI-bearing (per-flow) QER selected by CP.
     * It carries the correct MBR/GBR for flow-level trTCM metering. */
    const UPDK_QER *qer = pdr ? pdr->qer : NULL;
    if (!qer || !qer->flags.maximumBitrate) return;

    bool has_fd = pdr->has_fd;

    /* Use the same key that the DL policing path uses for ftSearch().
     * pdr->meter_key was precomputed by UPF-C from the same port mapping,
     * so insert and lookup are always consistent. */
    uint32_t key = has_fd ? pdr->meter_key
                          : (uint32_t)SourceInterfaceToPort(pdr->pdi.sourceInterface);

    /* Only add on first miss — subsequent packets for the same key are a no-op */
    if (ftSearch(key) >= 0) return;
    if (unlikely(trTCMidx >= APP_FLOWS_MAX)) {
        UTLT_Warning("TRTCM flow table full; cannot add key %u", key);
        return;
    }

    UTLT_Info("QER ID: %u key: %u", qer->qerId, key);

    struct rte_meter_trtcm_params trtcm_params = app_trtcm_params;
    bool has_gbr = qer->flags.guaranteedBitrate;

    uint64_t mbr = is_uplink ? qer->maximumBitrate.ul :
                               qer->maximumBitrate.dl;
    trtcm_params.pir = (uint64_t)mbr * 1000 / 8;
    trtcm_params.pbs = trtcm_bucket_depth(mbr);

    if (has_gbr) {
        uint64_t gbr = is_uplink ? qer->guaranteedBitrate.ul :
                                   qer->guaranteedBitrate.dl;
        trtcm_params.cir = (uint64_t)gbr * 1000 / 8;
        trtcm_params.cbs = trtcm_bucket_depth(gbr);
    } else {
        trtcm_params.cir = 1;
        trtcm_params.cbs = MIN_TOKEN_BUCKET_DEPTH;
    }

    int rtn = rte_meter_trtcm_profile_config(&app_flow_trtcm_profiles[trTCMidx],
                                             &trtcm_params);
    if (rtn) {
        UTLT_Warning("TRTCM profile config failed for key %u: %d", key, rtn);
        return;
    }
    rtn = rte_meter_trtcm_config(&app_flows[trTCMidx],
                                 &app_flow_trtcm_profiles[trTCMidx]);
    if (rtn) {
        UTLT_Warning("TRTCM flow config failed for key %u: %d", key, rtn);
        return;
    }
    app_flow_has_gbr[trTCMidx] = has_gbr;

    if (!ftAddEntry(key, trTCMidx)) {
        UTLT_Warning("FT add failed");
        return;
    }
    UTLT_Info("Successfully add %u(%d) %u", key, hashFunc(key), trTCMidx);

    if (is_uplink) {
        UTLT_Info("Find MBR (UL: %lu) in QERs", qer->maximumBitrate.ul);
        if (qer->flags.guaranteedBitrate)
            UTLT_Info("Find GBR (UL: %lu) in QERs", qer->guaranteedBitrate.ul);
    } else {
        UTLT_Info("Find MBR (DL: %lu) in QERs", qer->maximumBitrate.dl);
        if (qer->flags.guaranteedBitrate)
            UTLT_Info("Find GBR (DL: %lu) in QERs", qer->guaranteedBitrate.dl);
    }

    UTLT_Info("TRTCM params: %lu %lu %lu %lu\n",
              (unsigned long)trtcm_params.cir,
              (unsigned long)trtcm_params.pir,
              (unsigned long)trtcm_params.cbs,
              (unsigned long)trtcm_params.pbs);

    trTCMidx++;
}

/* Return ue_table index, or -1 */
static inline int
ueHashSearch(uint32_t ue_ip) {
    int idx = ueHashFunc(ue_ip);
    int start = idx;
    while (ueHashSlotInUse(idx)) {
        if (ue_hash[idx].ue_ip == ue_ip)
            return ue_hash[idx].ue_idx;
        idx = (idx + 1) % MAX_UE;
        if (idx == start) break;
    }
    return -1;
}

static inline bool
ueHashInsert(uint32_t ue_ip, int ue_idx) {
    if (ueHashSearch(ue_ip) >= 0) return false; /* already present */
    int idx = ueHashFunc(ue_ip);
    int start = idx;

    while (ueHashSlotInUse(idx)) {
        idx = (idx + 1) % MAX_UE;
        if (idx == start)
            return false;
    }
    ue_hash[idx].ue_ip  = ue_ip;
    ue_hash[idx].ue_idx = ue_idx;
    ueHashSetInUse(idx, true);
    return true;
}

/* Legacy wrapper — now O(1) via hash */
int
findIndexByUeIpAddress(uint32_t ue_ip) {
    return ueHashSearch(ue_ip);
}

bool
refreshUeSessionAmbr(int index, uint64_t session_ambr,
                     bool conflicting_rates) {
    bool rate_changed;
    bool new_conflict;

    if (unlikely(index < 0 || index >= MAX_UE))
        return false;

    rte_spinlock_lock(&ue_tb_locks[index]);
    if (unlikely(!ueTokenIndexValid(index))) {
        rte_spinlock_unlock(&ue_tb_locks[index]);
        return false;
    }

    rate_changed = ue_table[index].session_ambr != session_ambr;
    new_conflict = conflicting_rates &&
                   !ue_table[index].session_ambr_conflict;
    if (rate_changed) {
        uint64_t old_rate = ue_table[index].session_ambr;

        ue_table[index].session_ambr = session_ambr;
        initBucket(&ue_table[index].session_ambr_tb, session_ambr,
                   rte_get_tsc_cycles());
        UTLT_Warning("UE %u Session-AMBR changed from %" PRIu64
                     " to %" PRIu64
                     " Kbps; token state reset and a full burst is temporarily available",
                     ue_table[index].ue_ip, old_rate, session_ambr);
    }
    if (new_conflict) {
        UTLT_Warning("UE %u has conflicting Non-GBR QER DL rates; using largest Session-AMBR %"
                     PRIu64 " Kbps", ue_table[index].ue_ip, session_ambr);
    }
    ue_table[index].session_ambr_conflict = conflicting_rates;
    rte_spinlock_unlock(&ue_tb_locks[index]);
    return true;
}

bool
refreshUeGbrQer(int index, uint32_t qer_id, uint8_t qfi,
                uint64_t gfbr, uint64_t mfbr) {
    struct gbr_qer_tb *qer = NULL;
    struct gbr_qer_tb *free_qer = NULL;
    uint64_t now;

    if (unlikely(index < 0 || index >= MAX_UE || qer_id == 0 ||
                 gfbr == 0 || mfbr == 0))
        return false;

    rte_spinlock_lock(&ue_tb_locks[index]);
    if (unlikely(!ueTokenIndexValid(index))) {
        rte_spinlock_unlock(&ue_tb_locks[index]);
        return false;
    }

    for (int qer_idx = 0; qer_idx < SHAPER_MAX_GBR_QERS_PER_UE; qer_idx++) {
        struct gbr_qer_tb *candidate =
            &ue_table[index].gbr_qers[qer_idx];

        if (candidate->used && candidate->qer_id == qer_id) {
            qer = candidate;
            break;
        }
        if (!candidate->used && free_qer == NULL)
            free_qer = candidate;
    }

    if (qer == NULL) {
        if (free_qer == NULL) {
            rte_spinlock_unlock(&ue_tb_locks[index]);
            UTLT_Warning("UE %u GBR QER table full; cannot add QER %u",
                         ue_table[index].ue_ip, qer_id);
            return false;
        }

        qer = free_qer;
        now = rte_get_tsc_cycles();
        memset(qer, 0, sizeof(*qer));
        qer->used = true;
        qer->qer_id = qer_id;
        qer->qfi = qfi;
        qer->gfbr = gfbr;
        qer->mfbr = mfbr;
        initBucket(&qer->gfbr_tb, gfbr, now);
        initBucket(&qer->mfbr_tb, mfbr, now);
        UTLT_Info("UE %u GBR QER %u configured: QFI=%u GFBR=%" PRIu64
                  " MFBR=%" PRIu64 " Kbps",
                  ue_table[index].ue_ip, qer_id, qfi, gfbr, mfbr);
        if (gfbr > mfbr) {
            UTLT_Warning("UE %u GBR QER %u has GFBR %" PRIu64
                         " above MFBR %" PRIu64
                         " Kbps; MFBR remains the aggregate hard limit",
                         ue_table[index].ue_ip, qer_id, gfbr, mfbr);
        }
        rte_spinlock_unlock(&ue_tb_locks[index]);
        return true;
    }

    if (qer->qfi != qfi) {
        UTLT_Warning("UE %u GBR QER %u changed QFI from %u to %u",
                     ue_table[index].ue_ip, qer_id, qer->qfi, qfi);
        qer->qfi = qfi;
    }
    if (qer->gfbr != gfbr || qer->mfbr != mfbr) {
        uint64_t old_gfbr = qer->gfbr;
        uint64_t old_mfbr = qer->mfbr;

        now = rte_get_tsc_cycles();
        qer->gfbr = gfbr;
        qer->mfbr = mfbr;
        initBucket(&qer->gfbr_tb, gfbr, now);
        initBucket(&qer->mfbr_tb, mfbr, now);
        UTLT_Warning("UE %u GBR QER %u changed GFBR/MFBR from %" PRIu64
                     "/%" PRIu64 " to %" PRIu64 "/%" PRIu64
                     " Kbps; token state reset and a full burst is temporarily available",
                     ue_table[index].ue_ip, qer_id, old_gfbr, old_mfbr,
                     gfbr, mfbr);
        if (gfbr > mfbr) {
            UTLT_Warning("UE %u GBR QER %u has GFBR %" PRIu64
                         " above MFBR %" PRIu64
                         " Kbps; MFBR remains the aggregate hard limit",
                         ue_table[index].ue_ip, qer_id, gfbr, mfbr);
        }
    }

    rte_spinlock_unlock(&ue_tb_locks[index]);
    return true;
}

int
addEntrybyUeIp(uint32_t ue_ip, uint64_t session_ambr,
               bool conflicting_rates) {
    int added_idx = -1;
    int existing_idx;

    rte_spinlock_lock(&ue_table_lock);
    existing_idx = ueHashSearch(ue_ip);
    if (existing_idx >= 0) {
        rte_spinlock_unlock(&ue_table_lock);
        refreshUeSessionAmbr(existing_idx, session_ambr,
                            conflicting_rates);
        return existing_idx;
    }

    for (int i = 0; i < MAX_UE; i++) {
        if (ue_table[i].ue_ip == 0) { // find unused
            uint64_t now = rte_get_tsc_cycles();

            rte_spinlock_lock(&ue_tb_locks[i]);
            memset(&ue_table[i], 0, sizeof(ue_table[i]));
            ue_table[i].session_ambr = session_ambr;
            ue_table[i].session_ambr_conflict = conflicting_rates;
            initBucket(&ue_table[i].session_ambr_tb, session_ambr, now);
            ue_table[i].ue_ip = ue_ip;
            rte_spinlock_unlock(&ue_tb_locks[i]);
            if (ueHashInsert(ue_ip, i)) {
                UTLT_Info("UE %u Session-AMBR configured: %" PRIu64
                          " Kbps", ue_ip, session_ambr);
                if (conflicting_rates) {
                    UTLT_Warning("UE %u has conflicting Non-GBR QER DL rates; using largest Session-AMBR %"
                                 PRIu64 " Kbps", ue_ip, session_ambr);
                }
                added_idx = i;
            } else {
                rte_spinlock_lock(&ue_tb_locks[i]);
                memset(&ue_table[i], 0, sizeof(ue_table[i]));
                rte_spinlock_unlock(&ue_tb_locks[i]);
                added_idx = ueHashSearch(ue_ip);
            }
            break;
        }
    }
    rte_spinlock_unlock(&ue_table_lock);
    return added_idx;  // Return the allocated index, or -1 if table full
}

bool
removeEntrybyUeIp(uint32_t ue_ip) {
    int removed_idx;

    rte_spinlock_lock(&ue_table_lock);
    removed_idx = ueHashSearch(ue_ip);
    if (removed_idx < 0) {
        rte_spinlock_unlock(&ue_table_lock);
        return false;
    }

    rte_spinlock_lock(&ue_tb_locks[removed_idx]);
    memset(&ue_table[removed_idx], 0, sizeof(ue_table[removed_idx]));
    rte_spinlock_unlock(&ue_tb_locks[removed_idx]);

    /* Linear-probing lookups cannot simply clear one occupied hash slot: it
     * could make entries later in that probe chain unreachable. Session
     * deletion is rare, so rebuild the small fixed hash table in place. */
    for (int hash_idx = 0; hash_idx < MAX_UE; hash_idx++)
        ueHashSetInUse(hash_idx, false);
    for (int ue_idx = 0; ue_idx < MAX_UE; ue_idx++) {
        if (ue_table[ue_idx].ue_ip != 0 &&
            !ueHashInsert(ue_table[ue_idx].ue_ip, ue_idx)) {
            UTLT_Error("Failed to rebuild UE shaper hash for UE %u",
                       ue_table[ue_idx].ue_ip);
        }
    }

    rte_spinlock_unlock(&ue_table_lock);
    return true;
}

bool
sessionAmbrCanFitPacket(int index, uint32_t pkt_len) {
    bool can_fit;

    if (unlikely(index < 0 || index >= MAX_UE))
        return false;

    rte_spinlock_lock(&ue_tb_locks[index]);
    if (unlikely(!ueTokenIndexValid(index))) {
        rte_spinlock_unlock(&ue_tb_locks[index]);
        return false;
    }

    can_fit = bucketCanFitPacket(&ue_table[index].session_ambr_tb,
                                 pkt_len);
    rte_spinlock_unlock(&ue_tb_locks[index]);
    return can_fit;
}

bool
gbrGuaranteedCanFitPacket(int index, uint32_t qer_id, uint32_t pkt_len) {
    struct gbr_qer_tb *qer;
    bool can_fit = false;

    if (unlikely(index < 0 || index >= MAX_UE))
        return false;

    rte_spinlock_lock(&ue_tb_locks[index]);
    if (unlikely(!ueTokenIndexValid(index))) {
        rte_spinlock_unlock(&ue_tb_locks[index]);
        return false;
    }

    qer = findGbrQerLocked(index, qer_id);
    if (qer != NULL) {
        can_fit = bucketCanFitPacket(&qer->gfbr_tb, pkt_len) &&
                  bucketCanFitPacket(&qer->mfbr_tb, pkt_len);
    }

    rte_spinlock_unlock(&ue_tb_locks[index]);
    return can_fit;
}

bool
gbrExcessCanFitPacket(int index, uint32_t qer_id, uint32_t pkt_len) {
    struct gbr_qer_tb *qer;
    bool can_fit = false;

    if (unlikely(index < 0 || index >= MAX_UE))
        return false;

    rte_spinlock_lock(&ue_tb_locks[index]);
    if (unlikely(!ueTokenIndexValid(index))) {
        rte_spinlock_unlock(&ue_tb_locks[index]);
        return false;
    }

    qer = findGbrQerLocked(index, qer_id);
    if (qer != NULL)
        can_fit = bucketCanFitPacket(&qer->mfbr_tb, pkt_len);

    rte_spinlock_unlock(&ue_tb_locks[index]);
    return can_fit;
}

bool
consume_session_ambr(int index, uint32_t pkt_len) {
    struct tb_config *session_tb;
    bool consumed = false;

    if (unlikely(index < 0 || index >= MAX_UE))
        return false;

    rte_spinlock_lock(&ue_tb_locks[index]);
    if (unlikely(!ueTokenIndexValid(index))) {
        rte_spinlock_unlock(&ue_tb_locks[index]);
        return false;
    }

    session_tb = &ue_table[index].session_ambr_tb;
    shaper_update_bucket_tokens(session_tb, rte_get_tsc_cycles());
    if (session_tb->tb_tokens >= pkt_len) {
        session_tb->tb_tokens -= pkt_len;
        consumed = true;
    }

    rte_spinlock_unlock(&ue_tb_locks[index]);
    return consumed;
}

bool
consume_gbr_guaranteed(int index, uint32_t qer_id, uint32_t pkt_len) {
    struct gbr_qer_tb *qer;
    bool consumed = false;

    if (unlikely(index < 0 || index >= MAX_UE))
        return false;

    rte_spinlock_lock(&ue_tb_locks[index]);
    if (unlikely(!ueTokenIndexValid(index))) {
        rte_spinlock_unlock(&ue_tb_locks[index]);
        return false;
    }

    qer = findGbrQerLocked(index, qer_id);
    if (qer != NULL) {
        uint64_t now = rte_get_tsc_cycles();

        shaper_update_bucket_tokens(&qer->gfbr_tb, now);
        shaper_update_bucket_tokens(&qer->mfbr_tb, now);
        if (qer->gfbr_tb.tb_tokens >= pkt_len &&
            qer->mfbr_tb.tb_tokens >= pkt_len) {
            qer->gfbr_tb.tb_tokens -= pkt_len;
            qer->mfbr_tb.tb_tokens -= pkt_len;
            consumed = true;
        }
    }

    rte_spinlock_unlock(&ue_tb_locks[index]);
    return consumed;
}

bool
consume_gbr_excess(int index, uint32_t qer_id, uint32_t pkt_len) {
    struct gbr_qer_tb *qer;
    bool consumed = false;

    if (unlikely(index < 0 || index >= MAX_UE))
        return false;

    rte_spinlock_lock(&ue_tb_locks[index]);
    if (unlikely(!ueTokenIndexValid(index))) {
        rte_spinlock_unlock(&ue_tb_locks[index]);
        return false;
    }

    qer = findGbrQerLocked(index, qer_id);
    if (qer != NULL) {
        shaper_update_bucket_tokens(&qer->mfbr_tb, rte_get_tsc_cycles());
        if (qer->mfbr_tb.tb_tokens >= pkt_len) {
            qer->mfbr_tb.tb_tokens -= pkt_len;
            consumed = true;
        }
    }

    rte_spinlock_unlock(&ue_tb_locks[index]);
    return consumed;
}
