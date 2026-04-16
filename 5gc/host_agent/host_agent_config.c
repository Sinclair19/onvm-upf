/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include <yaml.h>

#include "host_agent_config.h"

static yaml_node_t *
doc_root(yaml_document_t *doc)
{
    if (!doc || doc->nodes.top <= doc->nodes.start)
        return NULL;
    return yaml_document_get_root_node(doc);
}

static yaml_node_t *
map_get(yaml_document_t *doc, yaml_node_t *map, const char *key)
{
    if (!map || map->type != YAML_MAPPING_NODE)
        return NULL;

    for (yaml_node_pair_t *p = map->data.mapping.pairs.start;
         p < map->data.mapping.pairs.top; ++p) {
        yaml_node_t *k = yaml_document_get_node(doc, p->key);
        yaml_node_t *v = yaml_document_get_node(doc, p->value);

        if (!k || k->type != YAML_SCALAR_NODE)
            continue;
        if (k->data.scalar.value &&
            strcmp((const char *)k->data.scalar.value, key) == 0)
            return v;
    }

    return NULL;
}

static int
copy_scalar(yaml_node_t *node, char *dst, size_t dst_len, const char *field_name)
{
    if (!node)
        return 0;

    if (node->type != YAML_SCALAR_NODE) {
        fprintf(stderr,
                "[HOST_AGENT][CONFIG] %s must be a scalar string\n",
                field_name);
        return -1;
    }

    if (!dst || dst_len == 0)
        return -1;

    snprintf(dst, dst_len, "%s", (const char *)node->data.scalar.value);
    return 0;
}

static int
do_parse(yaml_document_t *doc,
         char *pci_addr,
         size_t pci_addr_len,
         char *server_name,
         size_t server_name_len)
{
    yaml_node_t *root = doc_root(doc);
    yaml_node_t *cfg;
    yaml_node_t *host_agent_cfg;

    if (!root || root->type != YAML_MAPPING_NODE) {
        fprintf(stderr, "[HOST_AGENT][CONFIG] YAML root must be a mapping\n");
        return -1;
    }

    cfg = map_get(doc, root, "configuration");
    if (!cfg || cfg->type != YAML_MAPPING_NODE) {
        fprintf(stderr,
                "[HOST_AGENT][CONFIG] missing configuration mapping\n");
        return -1;
    }

    host_agent_cfg = map_get(doc, cfg, "host_agent");
    if (host_agent_cfg) {
        if (host_agent_cfg->type != YAML_MAPPING_NODE) {
            fprintf(stderr,
                    "[HOST_AGENT][CONFIG] configuration.host_agent must be a mapping\n");
            return -1;
        }
        cfg = host_agent_cfg;
    }

    if (copy_scalar(map_get(doc, cfg, "pci_addr"),
                    pci_addr,
                    pci_addr_len,
                    "pci_addr") != 0) {
        return -1;
    }

    if (copy_scalar(map_get(doc, cfg, "server_name"),
                    server_name,
                    server_name_len,
                    "server_name") != 0) {
        return -1;
    }

    return 0;
}

int
HostAgent_LoadAndParseConfig(const char *path,
                             char *pci_addr,
                             size_t pci_addr_len,
                             char *server_name,
                             size_t server_name_len)
{
    FILE *fp;
    yaml_parser_t parser;
    yaml_document_t document;
    int rc;

    fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr,
                "[HOST_AGENT][CONFIG] cannot open config file: %s\n",
                path);
        return -1;
    }

    if (!yaml_parser_initialize(&parser)) {
        fclose(fp);
        fprintf(stderr,
                "[HOST_AGENT][CONFIG] yaml_parser_initialize failed\n");
        return -1;
    }

    yaml_parser_set_input_file(&parser, fp);

    if (!yaml_parser_load(&parser, &document)) {
        yaml_parser_delete(&parser);
        fclose(fp);
        fprintf(stderr,
                "[HOST_AGENT][CONFIG] yaml_parser_load failed (malformed YAML?)\n");
        return -1;
    }

    rc = do_parse(&document,
                  pci_addr,
                  pci_addr_len,
                  server_name,
                  server_name_len);

    yaml_document_delete(&document);
    yaml_parser_delete(&parser);
    fclose(fp);

    return rc == 0 ? 0 : -1;
}
