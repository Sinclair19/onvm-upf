/*********************************************************************
 *                     openNetVM
 *              https://sdnfv.github.io
 *
 *   BSD LICENSE
 *
 *   Copyright(c)
 *            2015-2019 George Washington University
 *            2015-2019 University of California Riverside
 *            2010-2019 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * The name of the author may not be used to endorse or promote
 *       products derived from this software without specific prior written
 *       permission.
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
 ********************************************************************/

/******************************************************************************
                               onvm_wakemgr.c

       First-stage UPF-U RX queue monitor. This thread intentionally does
       not use semaphores, shared sleep flags, or alter NF execution state.

******************************************************************************/

#include <limits.h>
#include <string.h>

#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_ring.h>

#include "onvm_mgr.h"
#include "onvm_wakemgr.h"

#define UPF_U_NF_TAG "upf_u"
#define UPF_U_RX_SCAN_INTERVAL_US 10000
#define UPF_U_RX_HEARTBEAT_INTERVAL_US 1000000

int
onvm_wakemgr_main(void *arg) {
        struct onvm_wakemgr_ctx *ctx = (struct onvm_wakemgr_ctx *)arg;
        unsigned last_queue_size[MAX_NFS];
        uint64_t last_log_tsc[MAX_NFS] = {0};
        const uint64_t heartbeat_cycles =
            (rte_get_timer_hz() * UPF_U_RX_HEARTBEAT_INTERVAL_US) / 1000000;
        unsigned i;

        if (ctx == NULL || ctx->keep_running == NULL) {
                RTE_LOG(ERR, APP, "UPF-U RX monitor received an invalid context\n");
                return -1;
        }

        for (i = 0; i < MAX_NFS; i++)
                last_queue_size[i] = UINT_MAX;

        RTE_LOG(INFO, APP, "Socket %d, Core %d: Running UPF-U RX monitor\n",
                rte_socket_id(), rte_lcore_id());

        while (*ctx->keep_running) {
                const uint64_t now = rte_get_timer_cycles();

                for (i = 1; i < MAX_NFS; i++) {
                        struct onvm_nf *nf = &nfs[i];
                        unsigned queue_size;

                        if (!onvm_nf_is_valid(nf) || nf->tag == NULL ||
                            strcmp(nf->tag, UPF_U_NF_TAG) != 0 || nf->rx_q == NULL) {
                                last_queue_size[i] = UINT_MAX;
                                last_log_tsc[i] = 0;
                                continue;
                        }

                        queue_size = rte_ring_count(nf->rx_q);
                        if (queue_size == last_queue_size[i] &&
                            now - last_log_tsc[i] < heartbeat_cycles)
                                continue;

                        RTE_LOG(INFO, APP,
                                "UPF-U RX monitor: instance=%u service=%u queue_size=%u\n",
                                (unsigned)nf->instance_id, (unsigned)nf->service_id,
                                queue_size);
                        last_queue_size[i] = queue_size;
                        last_log_tsc[i] = now;
                }

                rte_delay_us_sleep(UPF_U_RX_SCAN_INTERVAL_US);
        }

        RTE_LOG(INFO, APP, "Socket %d, Core %d: UPF-U RX monitor done\n",
                rte_socket_id(), rte_lcore_id());
        return 0;
}
