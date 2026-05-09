#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifndef UPF_C_SERVICE_ID
#define UPF_C_SERVICE_ID  2
#endif

#define UPF_MAX_WORKERS 32
#define UPF_INVALID_SERVICE_ID UINT16_MAX

enum {
        UPF_EVENT_SET_BUFFER       = 0xA0,
        UPF_EVENT_CLEAR_AND_DRAIN  = 0xA1,
        EVT_CLS_GC_REQ = 0x4201,
        EVT_CLS_GC_ACK = 0x4202,
};

int UpfSendEvt1(uint16_t dest_sid, uint32_t type, uintptr_t a0);
int UpfSendEvt2(uint16_t dest_sid, uint32_t type, uintptr_t a0, uintptr_t a1);

void UpfWorkerConfigReset(void);
int UpfWorkerConfigSet(const uint16_t *service_ids, uint16_t count);
uint16_t UpfWorkerCount(void);
uint16_t UpfWorkerServiceIdAt(uint16_t index);
bool UpfWorkerServiceValid(uint16_t service_id);
uint16_t UpfSelectWorkerServiceIdRoundRobin(void);
uint16_t UpfSelectWorkerServiceIdByTeid(uint32_t teid);
uint16_t UpfBroadcastEvt1ToWorkers(uint32_t type, uintptr_t a0);
uint16_t UpfBroadcastEvt2ToWorkers(uint32_t type, uintptr_t a0, uintptr_t a1);

