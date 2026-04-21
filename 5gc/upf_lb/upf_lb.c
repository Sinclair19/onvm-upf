#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <rte_common.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

#include "gtp.h"
#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"
#include "upf_context.h"
#include "upf_events.h"
#include "utlt_debug.h"

#include "upf_lb_config.h"

#define NF_TAG "upf_lb"

typedef struct {
    uint64_t non_ipv4_drop;
    uint64_t malformed_gtpu_drop;
    uint64_t ul_worker_miss_drop;
    uint64_t dl_session_miss_drop;
    uint64_t worker_packets[UPF_MAX_WORKERS];
} upf_lb_stats_t;

static upf_lb_stats_t g_upf_lb_stats;

static inline int
worker_index_for_service(uint16_t service_id) {
    for (uint16_t i = 0; i < UpfWorkerCount(); i++) {
        if (UpfWorkerServiceIdAt(i) == service_id) {
            return (int)i;
        }
    }
    return -1;
}

static inline uint16_t
select_ul_worker(const gtp_parse_result_t *gtp_info) {
    UpfSession *session = UpfSessionFindByTeid(rte_cpu_to_be_32(gtp_info->teid));
    if (session) {
        return UpfSessionEnsureWorkerServiceId(session, gtp_info->teid);
    }
    return UpfSelectWorkerServiceIdByTeid(gtp_info->teid);
}

static inline uint16_t
select_dl_worker(struct rte_ipv4_hdr *iph) {
    UpfSession *session = UpfSessionFindByUeIP(iph->dst_addr);
    if (!session) {
        return UPF_INVALID_SERVICE_ID;
    }
    return UpfSessionEnsureWorkerServiceId(session, rte_be_to_cpu_32(session->teid));
}

static int
packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta,
               struct onvm_nf_local_ctx *nf_local_ctx) {
    (void)nf_local_ctx;

    meta->action = ONVM_NF_ACTION_DROP;

    struct rte_ether_hdr *eth = onvm_pkt_ether_hdr(pkt);
    if (!eth || rte_be_to_cpu_16(eth->ether_type) != RTE_ETHER_TYPE_IPV4) {
        g_upf_lb_stats.non_ipv4_drop++;
        return 0;
    }

    struct rte_ipv4_hdr *iph = onvm_pkt_ipv4_hdr(pkt);
    if (!iph) {
        g_upf_lb_stats.non_ipv4_drop++;
        return 0;
    }

    uint16_t owner_service_id = UPF_INVALID_SERVICE_ID;

    if (iph->dst_addr == g_upf_lb_access_ip_be) {
        gtp_parse_result_t gtp_info = {0};
        if (parse_gtpu_once(pkt, &gtp_info) < 0 || !gtp_info.valid) {
            g_upf_lb_stats.malformed_gtpu_drop++;
            return 0;
        }

        owner_service_id = select_ul_worker(&gtp_info);
        if (owner_service_id == UPF_INVALID_SERVICE_ID) {
            g_upf_lb_stats.ul_worker_miss_drop++;
            return 0;
        }
    } else {
        owner_service_id = select_dl_worker(iph);
        if (owner_service_id == UPF_INVALID_SERVICE_ID) {
            g_upf_lb_stats.dl_session_miss_drop++;
            return 0;
        }
    }

    int worker_index = worker_index_for_service(owner_service_id);
    if (worker_index < 0) {
        g_upf_lb_stats.ul_worker_miss_drop++;
        return 0;
    }

    g_upf_lb_stats.worker_packets[worker_index]++;
    meta->action = ONVM_NF_ACTION_TONF;
    meta->destination = owner_service_id;
    return 0;
}

int
main(int argc, char *argv[]) {
    struct onvm_nf_local_ctx *nf_local_ctx;
    struct onvm_nf_function_table *nf_function_table;
    int arg_offset;

    nf_local_ctx = onvm_nflib_init_nf_local_ctx();
    onvm_nflib_start_signal_handler(nf_local_ctx, NULL);

    nf_function_table = onvm_nflib_init_nf_function_table();
    nf_function_table->pkt_handler = &packet_handler;

    if ((arg_offset = onvm_nflib_init(argc, argv, NF_TAG, nf_local_ctx, nf_function_table)) < 0) {
        onvm_nflib_stop(nf_local_ctx);
        if (arg_offset == ONVM_SIGNAL_TERMINATION) {
            printf("Exiting due to user termination\n");
            return 0;
        }
        rte_exit(EXIT_FAILURE, "Failed ONVM init\n");
    }

    const char *config_path = "config/upf_lb.yaml";
    if (argc > arg_offset + 1) {
        config_path = argv[arg_offset + 1];
    }

    if (UpfLbLoadAndParseConfig(config_path) != 0) {
        rte_exit(EXIT_FAILURE, "Failed to load/parse UPF-LB config\n");
    }

    UTLT_SetLogLevel(g_upf_lb_log_level);

    if (g_upf_lb_service_id != UPF_INVALID_SERVICE_ID &&
        nf_local_ctx->nf->service_id != g_upf_lb_service_id) {
        UTLT_Warning("UPF-LB config service_id=%u but NF launched with service_id=%u",
                     g_upf_lb_service_id, nf_local_ctx->nf->service_id);
    }

    UpfSessionPoolInit();
    UeIpToUpfSessionMapInit();
    TeidToUpfSessionMapInit();

    onvm_nflib_run(nf_local_ctx);
    onvm_nflib_stop(nf_local_ctx);
    return 0;
}
