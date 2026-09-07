#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "onvm/upf/hw_offload_msg.h"

typedef struct { unsigned maximumBitrate:1; unsigned guaranteedBitrate:1; } qer_flags_t;
typedef struct { uint64_t ul, dl; } bitrate_t;
typedef struct UpfQER {
    uint32_t qerId;
    uint64_t hw_qer_id;
    qer_flags_t flags;
    bitrate_t maximumBitrate;
    bitrate_t guaranteedBitrate;
} UpfQER;
typedef UpfQER UPDK_QER;

typedef struct list_node { void *val; struct list_node *next; } list_node_t;
typedef struct { list_node_t *head; } list_t;
typedef struct { list_node_t *next; } list_iterator_t;
#define LIST_HEAD 0
static list_iterator_t *list_iterator_new(list_t *l, int unused) {
    (void)unused;
    list_iterator_t *it = malloc(sizeof(*it));
    if (it) it->next = l->head;
    return it;
}
static list_node_t *list_iterator_next(list_iterator_t *it) {
    list_node_t *n = it->next;
    if (n) it->next = n->next;
    return n;
}
static void list_iterator_destroy(list_iterator_t *it) { free(it); }

typedef struct { list_t *qer_list; } UpfSession;
typedef struct { UPDK_QER *qer; } UPDK_PDR;
#define UTLT_Debug(...) ((void)0)

#include "extracted_qer_helpers.h"

static unsigned failures;
#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #expr); ++failures; \
} } while (0)

static void add_qer(list_t *list, list_node_t *node, UpfQER *qer) {
    node->val = qer;
    node->next = list->head;
    list->head = node;
}
static UpfQER qer(uint32_t id, uint64_t hwid, uint64_t mul, uint64_t mdl,
                  uint64_t gul, uint64_t gdl) {
    UpfQER q = { .qerId=id, .hw_qer_id=hwid,
        .flags={ .maximumBitrate=(mul || mdl), .guaranteedBitrate=(gul || gdl) },
        .maximumBitrate={mul,mdl}, .guaranteedBitrate={gul,gdl} };
    return q;
}
static hw_offload_msg_t stamp(UpfSession *s, UPDK_QER *q, uint8_t dir) {
    hw_offload_msg_t m;
    memset(&m, 0, sizeof(m));
    UPDK_PDR p = { .qer=q };
    upf_stamp_qer_identity(s, &p, dir, &m);
    return m;
}

int main(void) {
    CHECK(sizeof(hw_offload_msg_t) == 104);
    CHECK(offsetof(hw_offload_msg_t, hw_qer_id) == 96);

    UpfQER session = qer(1, 1001, 9000, 8000, 0, 0);
    UpfQER smaller = qer(2, 1002, 4000, 7000, 0, 0);
    UpfQER flow_a = qer(3, 2001, 1000, 1100, 0, 0);
    UpfQER flow_b = qer(4, 2002, 1200, 1300, 0, 0);
    UpfQER gbr = qer(5, 3001, 3000, 3100, 500, 600);
    list_t list = {0}; list_node_t n1, n2;
    add_qer(&list, &n1, &session); add_qer(&list, &n2, &smaller);
    UpfSession s = { .qer_list=&list };

    hw_offload_msg_t m = stamp(&s, &gbr, HW_DIR_UPLINK);
    CHECK(m.hw_qer_id == 3001 && m.mbr_ul == 3000 && m.mbr_dl == 3100);
    CHECK(m.gbr_ul == 500 && m.gbr_dl == 600);

    hw_offload_msg_t a = stamp(&s, &flow_a, HW_DIR_UPLINK);
    hw_offload_msg_t b = stamp(&s, &flow_b, HW_DIR_UPLINK);
    CHECK(a.hw_qer_id == 1001 && b.hw_qer_id == 1001);
    CHECK(a.mbr_ul == 9000 && a.mbr_dl == 8000 && a.gbr_ul == 0);

    UpfQER ul_best = qer(6, 4001, 10000, 100, 0, 0);
    UpfQER dl_best = qer(7, 4002, 100, 10000, 0, 0);
    list_t directional = {0}; list_node_t nd1, nd2;
    add_qer(&directional, &nd1, &ul_best); add_qer(&directional, &nd2, &dl_best);
    UpfSession ds = { .qer_list=&directional };
    CHECK(stamp(&ds, &flow_a, HW_DIR_UPLINK).hw_qer_id == 4001);
    CHECK(stamp(&ds, &flow_a, HW_DIR_DOWNLINK).hw_qer_id == 4002);

    UpfQER other_session_qer = qer(1, 5001, 9000, 8000, 0, 0);
    list_t other_list = {0}; list_node_t on;
    add_qer(&other_list, &on, &other_session_qer);
    UpfSession other = { .qer_list=&other_list };
    CHECK(stamp(&s, &flow_a, HW_DIR_UPLINK).hw_qer_id !=
          stamp(&other, &flow_a, HW_DIR_UPLINK).hw_qer_id);

    m = stamp(NULL, &flow_a, HW_DIR_UPLINK);
    CHECK(m.hw_qer_id == 2001 && m.mbr_ul == 1000 && m.mbr_dl == 1100);

    m = stamp(NULL, NULL, HW_DIR_UPLINK);
    CHECK(m.hw_qer_id == 0 && m.mbr_ul == 0 && m.gbr_ul == 0);
    UPDK_PDR no_qer = {0}; memset(&m, 0, sizeof(m));
    upf_stamp_qer_identity(&s, &no_qer, HW_DIR_UPLINK, &m);
    CHECK(m.hw_qer_id == 1001); /* a session QER supplies non-GBR identity */
    UpfSession empty = {0}; memset(&m, 0, sizeof(m));
    upf_stamp_qer_identity(&empty, &no_qer, HW_DIR_UPLINK, &m);
    CHECK(m.hw_qer_id == 0);

    if (failures) return 1;
    puts("bf2 QER regression: all checks passed");
    return 0;
}
