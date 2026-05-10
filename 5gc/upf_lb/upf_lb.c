#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <rte_common.h>
#include <rte_arp.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>

#include "gtp.h"
#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"
#include "upf_context.h"
#include "upf_events.h"
#include "utlt_debug.h"

#include "upf_lb_config.h"

#define NF_TAG "upf_lb"
#define PKTMBUF_POOL_NAME "MProc_pktmbuf_pool"

typedef struct {
    uint64_t non_ipv4_drop;
    uint64_t malformed_gtpu_drop;
    uint64_t ul_worker_miss_drop;
    uint64_t dl_session_miss_drop;
    uint64_t worker_packets[UPF_MAX_WORKERS];
} upf_lb_stats_t;

static upf_lb_stats_t g_upf_lb_stats;
static struct rte_mempool *g_pktmbuf_pool;
static int g_upf_lb_bench_drop;

static inline int
worker_index_for_service(uint16_t service_id);

static inline int
is_local_dataplane_ip(uint32_t ip_be) {
    return ip_be == g_upf_lb_access_ip_be ||
           (g_upf_lb_core_ip_be != 0 && ip_be == g_upf_lb_core_ip_be);
}

static inline void
ensure_pktmbuf_pool(void) {
    if (!g_pktmbuf_pool) {
        g_pktmbuf_pool = rte_mempool_lookup(PKTMBUF_POOL_NAME);
    }
}

static int
send_arp_reply(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta,
               struct onvm_nf_local_ctx *nf_local_ctx) {
    struct rte_ether_hdr *eth = onvm_pkt_ether_hdr(pkt);
    if (!pkt || !meta || !nf_local_ctx || !nf_local_ctx->nf || !eth) {
        if (meta) {
            meta->action = ONVM_NF_ACTION_DROP;
        }
        return 0;
    }

    if (pkt->pkt_len < sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr)) {
        meta->action = ONVM_NF_ACTION_DROP;
        return 0;
    }

    struct rte_arp_hdr *arp = rte_pktmbuf_mtod_offset(
        pkt, struct rte_arp_hdr *, sizeof(struct rte_ether_hdr));
    if (!arp ||
        rte_be_to_cpu_16(arp->arp_hardware) != RTE_ARP_HRD_ETHER ||
        rte_be_to_cpu_16(arp->arp_protocol) != RTE_ETHER_TYPE_IPV4 ||
        arp->arp_hlen != RTE_ETHER_ADDR_LEN ||
        arp->arp_plen != sizeof(uint32_t)) {
        meta->action = ONVM_NF_ACTION_DROP;
        return 0;
    }

    if (rte_be_to_cpu_16(arp->arp_opcode) != RTE_ARP_OP_REQUEST ||
        !is_local_dataplane_ip(arp->arp_data.arp_tip)) {
        meta->action = ONVM_NF_ACTION_DROP;
        return 0;
    }

    ensure_pktmbuf_pool();
    if (!g_pktmbuf_pool) {
        UTLT_Error("UPF-LB cannot find mbuf pool %s", PKTMBUF_POOL_NAME);
        meta->action = ONVM_NF_ACTION_DROP;
        return 0;
    }

    struct rte_ether_addr local_mac;
    if (rte_eth_macaddr_get(pkt->port, &local_mac) < 0) {
        UTLT_Error("UPF-LB failed to get MAC for port %u", pkt->port);
        meta->action = ONVM_NF_ACTION_DROP;
        return 0;
    }

    struct rte_mbuf *reply = rte_pktmbuf_alloc(g_pktmbuf_pool);
    if (!reply) {
        meta->action = ONVM_NF_ACTION_DROP;
        return 0;
    }

    size_t pkt_size = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
    char *data = rte_pktmbuf_append(reply, pkt_size);
    if (!data) {
        rte_pktmbuf_free(reply);
        meta->action = ONVM_NF_ACTION_DROP;
        return 0;
    }

    struct rte_ether_hdr *out_eth = (struct rte_ether_hdr *)data;
    struct rte_arp_hdr *out_arp = (struct rte_arp_hdr *)(out_eth + 1);

    rte_ether_addr_copy(&local_mac, &out_eth->src_addr);
    rte_ether_addr_copy(&arp->arp_data.arp_sha, &out_eth->dst_addr);
    out_eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);

    out_arp->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
    out_arp->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    out_arp->arp_hlen = RTE_ETHER_ADDR_LEN;
    out_arp->arp_plen = sizeof(uint32_t);
    out_arp->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
    rte_ether_addr_copy(&local_mac, &out_arp->arp_data.arp_sha);
    out_arp->arp_data.arp_sip = arp->arp_data.arp_tip;
    rte_ether_addr_copy(&arp->arp_data.arp_sha, &out_arp->arp_data.arp_tha);
    out_arp->arp_data.arp_tip = arp->arp_data.arp_sip;

    struct onvm_pkt_meta *reply_meta =
        onvm_get_pkt_meta(reply, nf_local_ctx->nf->dynfield_offset);
    reply_meta->destination = pkt->port;
    reply_meta->action = ONVM_NF_ACTION_OUT;

    (void)onvm_nflib_return_pkt(nf_local_ctx->nf, reply);

    meta->action = ONVM_NF_ACTION_DROP;
    return 0;
}

static int
forward_arp_to_workers(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta,
                       struct onvm_nf_local_ctx *nf_local_ctx) {
    uint16_t worker_count = UpfWorkerCount();
    if (!pkt || !meta || !nf_local_ctx || !nf_local_ctx->nf || worker_count == 0) {
        if (meta) {
            meta->action = ONVM_NF_ACTION_DROP;
        }
        return 0;
    }

    ensure_pktmbuf_pool();

    for (uint16_t i = 1; i < worker_count; i++) {
        uint16_t worker_service_id = UpfWorkerServiceIdAt(i);
        if (worker_service_id == UPF_INVALID_SERVICE_ID || !g_pktmbuf_pool) {
            continue;
        }

        struct rte_mbuf *clone = rte_pktmbuf_clone(pkt, g_pktmbuf_pool);
        if (!clone) {
            continue;
        }

        struct onvm_pkt_meta *clone_meta =
            onvm_get_pkt_meta(clone, nf_local_ctx->nf->dynfield_offset);
        clone_meta->action = ONVM_NF_ACTION_TONF;
        clone_meta->destination = worker_service_id;

        int worker_index = worker_index_for_service(worker_service_id);
        if (worker_index >= 0) {
            g_upf_lb_stats.worker_packets[worker_index]++;
        }

        (void)onvm_nflib_return_pkt(nf_local_ctx->nf, clone);
    }

    uint16_t first_worker_service_id = UpfWorkerServiceIdAt(0);
    int worker_index = worker_index_for_service(first_worker_service_id);
    if (worker_index >= 0) {
        g_upf_lb_stats.worker_packets[worker_index]++;
    }

    meta->action = ONVM_NF_ACTION_TONF;
    meta->destination = first_worker_service_id;
    return 0;
}

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
    UpfSession *session = UpfSessionFindByTeidHost(gtp_info->teid);
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
    if (!eth) {
        g_upf_lb_stats.non_ipv4_drop++;
        return 0;
    }

    uint16_t ether_type = rte_be_to_cpu_16(eth->ether_type);
    if (ether_type == RTE_ETHER_TYPE_ARP) {
        struct rte_arp_hdr *arp = NULL;
        if (pkt->pkt_len >= sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr)) {
            arp = rte_pktmbuf_mtod_offset(pkt, struct rte_arp_hdr *,
                                          sizeof(struct rte_ether_hdr));
        }
        if (arp && rte_be_to_cpu_16(arp->arp_opcode) == RTE_ARP_OP_REQUEST &&
            is_local_dataplane_ip(arp->arp_data.arp_tip)) {
            return send_arp_reply(pkt, meta, nf_local_ctx);
        }
        return forward_arp_to_workers(pkt, meta, nf_local_ctx);
    }
    if (ether_type != RTE_ETHER_TYPE_IPV4) {
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

    if (g_upf_lb_bench_drop) {
        meta->action = ONVM_NF_ACTION_DROP;
        return 0;
    }

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

    struct onvm_configuration *onvm_config = onvm_nflib_get_onvm_config();
    nf_local_ctx->nf->dynfield_offset = onvm_config->dynfield_offset;

    const char *config_path = "config/upf_lb.yaml";
    if (argc > arg_offset + 1) {
        config_path = argv[arg_offset + 1];
    }

    if (UpfLbLoadAndParseConfig(config_path) != 0) {
        rte_exit(EXIT_FAILURE, "Failed to load/parse UPF-LB config\n");
    }

    UTLT_SetLogLevel(g_upf_lb_log_level);
    g_upf_lb_bench_drop = getenv("UPF_LB_BENCH_DROP") != NULL;
    if (g_upf_lb_bench_drop) {
        UTLT_Warning("UPF-LB benchmark drop mode enabled; packets are not forwarded to UPF-U");
    }

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
