#ifndef HOST_AGENT_CONFIG_H
#define HOST_AGENT_CONFIG_H

#include <stddef.h>

int
HostAgent_LoadAndParseConfig(const char *path,
                             char *pci_addr,
                             size_t pci_addr_len,
                             char *server_name,
                             size_t server_name_len);

#endif /* HOST_AGENT_CONFIG_H */
