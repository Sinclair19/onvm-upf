#ifndef UPF_LB_CONFIG_H
#define UPF_LB_CONFIG_H

#include <stdint.h>

extern uint32_t g_upf_lb_access_ip_be;
extern uint32_t g_upf_lb_core_ip_be;
extern uint16_t g_upf_lb_service_id;
extern char g_upf_lb_log_level[16];

int
UpfLbLoadAndParseConfig(const char *path);

#endif
