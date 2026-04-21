#include "upf_events.h"

#include <string.h>

#include <rte_malloc.h>

#include "onvm_nflib.h"
#include "utlt_event.h"

static uint16_t g_upf_worker_service_ids[UPF_MAX_WORKERS];
static uint16_t g_upf_worker_count = 0;

int
UpfSendEvt1(uint16_t dest_sid, uint32_t type, uintptr_t a0) {
    Event *e = (Event *)rte_calloc("upf_evt", 1, sizeof(*e), 0);
    if (!e) {
        return -1;
    }

    e->type = (uintptr_t)type;
    e->argc = 1;
    e->arg0 = a0;

    int rc = onvm_nflib_send_msg_to_nf(dest_sid, e);
    if (rc < 0) {
        rte_free(e);
    }
    return rc;
}

int
UpfSendEvt2(uint16_t dest_sid, uint32_t type, uintptr_t a0, uintptr_t a1) {
    Event *e = (Event *)rte_calloc("upf_evt", 1, sizeof(*e), 0);
    if (!e) {
        return -1;
    }

    e->type = (uintptr_t)type;
    e->argc = 2;
    e->arg0 = a0;
    e->arg1 = a1;

    int rc = onvm_nflib_send_msg_to_nf(dest_sid, e);
    if (rc < 0) {
        rte_free(e);
    }
    return rc;
}

void
UpfWorkerConfigReset(void) {
    memset(g_upf_worker_service_ids, 0, sizeof(g_upf_worker_service_ids));
    g_upf_worker_count = 0;
}

int
UpfWorkerConfigSet(const uint16_t *service_ids, uint16_t count) {
    UpfWorkerConfigReset();

    if (!service_ids || count == 0 || count > UPF_MAX_WORKERS) {
        return -1;
    }

    for (uint16_t i = 0; i < count; i++) {
        uint16_t sid = service_ids[i];
        if (sid == UPF_INVALID_SERVICE_ID || sid == UPF_C_SERVICE_ID) {
            UpfWorkerConfigReset();
            return -1;
        }

        for (uint16_t j = 0; j < i; j++) {
            if (g_upf_worker_service_ids[j] == sid) {
                UpfWorkerConfigReset();
                return -1;
            }
        }

        g_upf_worker_service_ids[i] = sid;
    }

    g_upf_worker_count = count;
    return 0;
}

uint16_t
UpfWorkerCount(void) {
    return g_upf_worker_count;
}

uint16_t
UpfWorkerServiceIdAt(uint16_t index) {
    if (index >= g_upf_worker_count) {
        return UPF_INVALID_SERVICE_ID;
    }
    return g_upf_worker_service_ids[index];
}

bool
UpfWorkerServiceValid(uint16_t service_id) {
    for (uint16_t i = 0; i < g_upf_worker_count; i++) {
        if (g_upf_worker_service_ids[i] == service_id) {
            return true;
        }
    }
    return false;
}

uint16_t
UpfSelectWorkerServiceIdByTeid(uint32_t teid) {
    if (g_upf_worker_count == 0) {
        return UPF_INVALID_SERVICE_ID;
    }

    return g_upf_worker_service_ids[teid % g_upf_worker_count];
}

uint16_t
UpfBroadcastEvt1ToWorkers(uint32_t type, uintptr_t a0) {
    uint16_t sent = 0;

    for (uint16_t i = 0; i < g_upf_worker_count; i++) {
        if (UpfSendEvt1(g_upf_worker_service_ids[i], type, a0) == 0) {
            sent++;
        }
    }

    return sent;
}

uint16_t
UpfBroadcastEvt2ToWorkers(uint32_t type, uintptr_t a0, uintptr_t a1) {
    uint16_t sent = 0;

    for (uint16_t i = 0; i < g_upf_worker_count; i++) {
        if (UpfSendEvt2(g_upf_worker_service_ids[i], type, a0, a1) == 0) {
            sent++;
        }
    }

    return sent;
}
