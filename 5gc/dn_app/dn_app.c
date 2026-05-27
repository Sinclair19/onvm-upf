/*********************************************************************
 *                     openNetVM
 *              https://sdnfv.github.io
 *
 *   BSD LICENSE
 *
 *   Copyright(c)
 *            2015-2019 George Washington University
 *            2015-2019 University of California Riverside
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * The name of the author may not be used to endorse or promote
 *       products derived from this software without specific prior
 *       written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * dn_app.c - a dummy DN app used to bounce packets back to CN
 ********************************************************************/

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <rte_common.h>
#include <rte_arp.h>
#include <rte_cycles.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_udp.h>

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"

#define NF_TAG "dn_app"

/* number of package between each print */
static uint32_t print_delay = 1000000;
static uint32_t app_ip_be;

static uint32_t total_packets = 0;
static uint64_t last_cycle;
static uint64_t cur_cycles;

/* shared data structure containing host port info */
extern struct port_info *ports;

static int
parse_ipv4_be(const char *s, uint32_t *out)
{
    struct in_addr addr;

    if (s == NULL || out == NULL || inet_pton(AF_INET, s, &addr) != 1)
        return -1;

    *out = addr.s_addr;
    return 0;
}

static const char *
ipv4_to_buf(uint32_t be_addr, char buf[16])
{
    inet_ntop(AF_INET, &be_addr, buf, 16);
    return buf;
}

static int
handle_arp_echo(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta)
{
    struct rte_ether_hdr *eth;
    struct rte_arp_hdr *arp;
    struct rte_ether_addr local_mac;
    char ip[16];

    eth = onvm_pkt_ether_hdr(pkt);
    if (eth == NULL ||
        rte_be_to_cpu_16(eth->ether_type) != RTE_ETHER_TYPE_ARP) {
        return 0;
    }

    if (pkt->pkt_len < sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr)) {
        meta->action = ONVM_NF_ACTION_DROP;
        return 1;
    }

    arp = rte_pktmbuf_mtod_offset(pkt, struct rte_arp_hdr *,
                                  sizeof(struct rte_ether_hdr));

    if (rte_be_to_cpu_16(arp->arp_opcode) != RTE_ARP_OP_REQUEST ||
        arp->arp_data.arp_tip != app_ip_be) {
        meta->action = ONVM_NF_ACTION_DROP;
        return 1;
    }

    if (rte_eth_macaddr_get(pkt->port, &local_mac) < 0) {
        meta->action = ONVM_NF_ACTION_DROP;
        return 1;
    }

    rte_ether_addr_copy(&eth->src_addr, &eth->dst_addr);
    rte_ether_addr_copy(&local_mac, &eth->src_addr);

    arp->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
    rte_ether_addr_copy(&arp->arp_data.arp_sha, &arp->arp_data.arp_tha);
    arp->arp_data.arp_tip = arp->arp_data.arp_sip;
    rte_ether_addr_copy(&local_mac, &arp->arp_data.arp_sha);
    arp->arp_data.arp_sip = app_ip_be;

    meta->action = ONVM_NF_ACTION_OUT;
    meta->destination = pkt->port;

    printf("[dn_app] arp reply ip=%s port=%u\n",
           ipv4_to_buf(app_ip_be, ip), pkt->port);
    return 1;
}

static void
log_udp_payload_seq(struct rte_mbuf *pkt, const char *tag) {
    static uint32_t logged = 0;
    struct rte_ipv4_hdr *iph = onvm_pkt_ipv4_hdr(pkt);

    if (iph == NULL || iph->next_proto_id != IPPROTO_UDP)
        return;

    uint8_t ihl = (iph->version_ihl & 0x0f) * 4;
    if (pkt->pkt_len < sizeof(struct rte_ether_hdr) + ihl + sizeof(struct rte_udp_hdr) + sizeof(uint32_t))
        return;

    struct rte_udp_hdr *udp = rte_pktmbuf_mtod_offset(
        pkt, struct rte_udp_hdr *, sizeof(struct rte_ether_hdr) + ihl);
    uint32_t *seqp = rte_pktmbuf_mtod_offset(
        pkt, uint32_t *, sizeof(struct rte_ether_hdr) + ihl + sizeof(struct rte_udp_hdr));
    uint32_t seq = rte_be_to_cpu_32(*seqp);

    if (logged < 16 || (total_packets % print_delay) == 0) {
        printf("[dn_app] %s seq=%" PRIu32 " %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u len=%u port=%u\n",
               tag,
               seq,
               ((uint8_t *)&iph->src_addr)[0], ((uint8_t *)&iph->src_addr)[1],
               ((uint8_t *)&iph->src_addr)[2], ((uint8_t *)&iph->src_addr)[3],
               rte_be_to_cpu_16(udp->src_port),
               ((uint8_t *)&iph->dst_addr)[0], ((uint8_t *)&iph->dst_addr)[1],
               ((uint8_t *)&iph->dst_addr)[2], ((uint8_t *)&iph->dst_addr)[3],
               rte_be_to_cpu_16(udp->dst_port),
               pkt->pkt_len, pkt->port);
        logged++;
    }
}

/*
 * Print a usage message
 */
static void
usage(const char *progname) {
    printf("Usage:\n");
    printf("%s [EAL args] -- [NF_LIB args] -- -p <print_delay>\n", progname);
    printf("%s -F <CONFIG_FILE.json> [EAL args] -- [NF_LIB args] -- [NF args]\n\n", progname);
    printf("Flags:\n");
    printf(" - `-p <print_delay>`: number of packets between each print, e.g. `-p 1` prints every packets.\n");
    printf(" - `-a <ip>`: IPv4 address to answer ARP for, default 192.168.3.2.\n");
}

/*
 * Parse the application arguments.
 */
static int
parse_app_args(int argc, char *argv[], const char *progname) {
    int c;

    while ((c = getopt(argc, argv, "p:a:")) != -1) {
        switch (c) {
            case 'p':
                print_delay = strtoul(optarg, NULL, 10);
                RTE_LOG(INFO, APP, "print_delay = %d\n", print_delay);
                break;
            case 'a':
                if (parse_ipv4_be(optarg, &app_ip_be) != 0) {
                    RTE_LOG(INFO, APP, "Invalid IPv4 address `%s'.\n", optarg);
                    return -1;
                }
                RTE_LOG(INFO, APP, "app_ip = %s\n", optarg);
                break;
            case '?':
                usage(progname);
                if (optopt == 'p' || optopt == 'a')
                    RTE_LOG(INFO, APP, "Option -%c requires an argument.\n", optopt);
                else if (isprint(optopt))
                    RTE_LOG(INFO, APP, "Unknown option `-%c'.\n", optopt);
                else
                    RTE_LOG(INFO, APP, "Unknown option character `\\x%x'.\n", optopt);
                return -1;
            default:
                usage(progname);
                return -1;
        }
    }
    return optind;
}

/*
 * This function displays stats. It uses ANSI terminal codes to clear
 * screen when called. It is called from a single non-master
 * thread in the server process, when the process is run with more
 * than one lcore enabled.
 */
static void
do_stats_display(struct rte_mbuf *pkt) {
    const char clr[] = {27, '[', '2', 'J', '\0'};
    const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};
    static uint64_t pkt_process = 0;
    struct rte_ipv4_hdr *ip;

    pkt_process += print_delay;

    /* Clear screen and move to top left */
    printf("%s%s", clr, topLeft);

    printf("PACKETS\n");
    printf("-----\n");
    printf("Port : %d\n", pkt->port);
    printf("Size : %d\n", pkt->pkt_len);
    printf("Hash : %u\n", pkt->hash.rss);
    printf("N°   : %" PRIu64 "\n", pkt_process);
    printf("\n\n");

    ip = onvm_pkt_ipv4_hdr(pkt);
    if (ip != NULL) {
        onvm_pkt_print(pkt);
    } else {
        printf("No IP4 header found\n");
    }
}

static int
callback_handler(__attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
    cur_cycles = rte_get_tsc_cycles();

    if (((cur_cycles - last_cycle) / rte_get_timer_hz()) > 5) {
        printf("Total packets received: %" PRIu32 "\n", total_packets);
        last_cycle = cur_cycles;
    }

    return 0;
}

static int
packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta,
               __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
    static uint32_t counter = 0;
    total_packets++;
    if (++counter == print_delay) {
        do_stats_display(pkt);
        counter = 0;
    }

    meta->action = ONVM_NF_ACTION_OUT;
    meta->destination = pkt->port;

    if (handle_arp_echo(pkt, meta)) {
        return 0;
    }

	struct rte_ipv4_hdr *iph = onvm_pkt_ipv4_hdr(pkt);
	if (iph) {
        log_udp_payload_seq(pkt, "rx");
		onvm_pkt_swap_ip_hdr(iph);
	}

    struct rte_udp_hdr *udp = onvm_pkt_udp_hdr(pkt);
    if (udp) {
        uint16_t src_port = udp->src_port;
        udp->src_port = udp->dst_port;
        udp->dst_port = src_port;
    }

	struct rte_ether_hdr *ether = onvm_pkt_ether_hdr(pkt);
	if (ether) {
		onvm_pkt_swap_ether_hdr(ether);
	}

    log_udp_payload_seq(pkt, "tx");

    return 0;
}

int
main(int argc, char *argv[]) {
    struct onvm_nf_local_ctx *nf_local_ctx;
    struct onvm_nf_function_table *nf_function_table;
    int arg_offset;
    const char *progname = argv[0];

    nf_local_ctx = onvm_nflib_init_nf_local_ctx();
    onvm_nflib_start_signal_handler(nf_local_ctx, NULL);

    nf_function_table = onvm_nflib_init_nf_function_table();
    nf_function_table->pkt_handler = &packet_handler;
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

    argc -= arg_offset;
    argv += arg_offset;

    if (parse_app_args(argc, argv, progname) < 0) {
        onvm_nflib_stop(nf_local_ctx);
        rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");
    }

    cur_cycles = rte_get_tsc_cycles();
    last_cycle = rte_get_tsc_cycles();
    if (app_ip_be == 0 && parse_ipv4_be("192.168.3.2", &app_ip_be) != 0) {
        rte_exit(EXIT_FAILURE, "Invalid default DN app IP\n");
    }

    onvm_nflib_run(nf_local_ctx);

    onvm_nflib_stop(nf_local_ctx);
    printf("If we reach here, program is ending\n");
    return 0;
}
