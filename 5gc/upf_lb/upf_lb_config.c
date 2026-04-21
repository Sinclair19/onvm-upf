#include "upf_lb_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <yaml.h>

#include "upf_events.h"
#include "utlt_debug.h"

uint32_t g_upf_lb_access_ip_be = 0;
uint16_t g_upf_lb_service_id = UPF_INVALID_SERVICE_ID;
char g_upf_lb_log_level[16] = "warning";

static int
parse_ipv4_address(const char *addr_str, uint32_t *out_ip_be) {
    unsigned long a, b, c, d;
    char tail = '\0';

    if (sscanf(addr_str, "%lu.%lu.%lu.%lu%c", &a, &b, &c, &d, &tail) != 4) {
        return -1;
    }
    if (a > 255 || b > 255 || c > 255 || d > 255) {
        return -1;
    }

    *out_ip_be = (uint32_t)((d << 24) | (c << 16) | (b << 8) | a);
    return 0;
}

static yaml_node_t *
doc_root(yaml_document_t *doc) {
    if (!doc || doc->nodes.top <= doc->nodes.start) {
        return NULL;
    }
    return yaml_document_get_root_node(doc);
}

static yaml_node_t *
map_get(yaml_document_t *doc, yaml_node_t *map, const char *key) {
    if (!map || map->type != YAML_MAPPING_NODE) {
        return NULL;
    }

    for (yaml_node_pair_t *p = map->data.mapping.pairs.start;
         p < map->data.mapping.pairs.top; ++p) {
        yaml_node_t *k = yaml_document_get_node(doc, p->key);
        yaml_node_t *v = yaml_document_get_node(doc, p->value);
        if (!k || k->type != YAML_SCALAR_NODE) {
            continue;
        }
        if (k->data.scalar.value &&
            strcmp((const char *)k->data.scalar.value, key) == 0) {
            return v;
        }
    }
    return NULL;
}

static const char *
scalar_str(yaml_node_t *n) {
    if (!n || n->type != YAML_SCALAR_NODE) {
        return NULL;
    }
    return (const char *)n->data.scalar.value;
}

static int
parse_worker_services(yaml_document_t *doc, yaml_node_t *cfg) {
    yaml_node_t *workers = map_get(doc, cfg, "upf_u_workers");
    if (!workers) {
        fprintf(stderr, "[UPF-LB][CONFIG] missing upf_u_workers\n");
        return -1;
    }

    uint16_t worker_ids[UPF_MAX_WORKERS];
    uint16_t worker_count = 0;

    if (workers->type == YAML_SEQUENCE_NODE) {
        for (yaml_node_item_t *item = workers->data.sequence.items.start;
             item < workers->data.sequence.items.top; ++item) {
            yaml_node_t *node = yaml_document_get_node(doc, *item);
            const char *value = scalar_str(node);
            if (!value || worker_count >= UPF_MAX_WORKERS) {
                return -1;
            }
            worker_ids[worker_count++] = (uint16_t)atoi(value);
        }
    } else {
        const char *value = scalar_str(workers);
        if (!value) {
            return -1;
        }
        worker_ids[worker_count++] = (uint16_t)atoi(value);
    }

    if (worker_count == 0 || UpfWorkerConfigSet(worker_ids, worker_count) < 0) {
        fprintf(stderr, "[UPF-LB][CONFIG] invalid upf_u_workers\n");
        return -1;
    }

    return 0;
}

static int
do_parse(yaml_document_t *doc) {
    yaml_node_t *root = doc_root(doc);
    if (!root || root->type != YAML_MAPPING_NODE) {
        return -1;
    }

    yaml_node_t *cfg = map_get(doc, root, "configuration");
    if (!cfg || cfg->type != YAML_MAPPING_NODE) {
        return -1;
    }

    yaml_node_t *log_level = map_get(doc, cfg, "log_level");
    const char *log_level_str = scalar_str(log_level);
    if (log_level_str && *log_level_str) {
        size_t len = strlen(log_level_str);
        if (len >= sizeof(g_upf_lb_log_level)) {
            len = sizeof(g_upf_lb_log_level) - 1;
        }
        memcpy(g_upf_lb_log_level, log_level_str, len);
        g_upf_lb_log_level[len] = '\0';
    }

    yaml_node_t *service_id = map_get(doc, cfg, "service_id");
    const char *service_id_str = scalar_str(service_id);
    if (service_id_str && *service_id_str) {
        g_upf_lb_service_id = (uint16_t)atoi(service_id_str);
    }

    yaml_node_t *dataplane = map_get(doc, cfg, "dataplane");
    if (!dataplane || dataplane->type != YAML_MAPPING_NODE) {
        fprintf(stderr, "[UPF-LB][CONFIG] missing dataplane\n");
        return -1;
    }

    yaml_node_t *access_ip = map_get(doc, dataplane, "upf_access_ip");
    const char *access_ip_str = scalar_str(access_ip);
    if (!access_ip_str || parse_ipv4_address(access_ip_str, &g_upf_lb_access_ip_be) != 0) {
        fprintf(stderr, "[UPF-LB][CONFIG] invalid upf_access_ip\n");
        return -1;
    }

    return parse_worker_services(doc, cfg);
}

int
UpfLbLoadAndParseConfig(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "[UPF-LB][CONFIG] cannot open %s\n", path);
        return -1;
    }

    yaml_parser_t parser;
    yaml_document_t document;

    if (!yaml_parser_initialize(&parser)) {
        fclose(fp);
        fprintf(stderr, "[UPF-LB][CONFIG] yaml_parser_initialize failed\n");
        return -1;
    }

    yaml_parser_set_input_file(&parser, fp);
    if (!yaml_parser_load(&parser, &document)) {
        yaml_parser_delete(&parser);
        fclose(fp);
        fprintf(stderr, "[UPF-LB][CONFIG] yaml_parser_load failed\n");
        return -1;
    }

    int rc = do_parse(&document);

    yaml_document_delete(&document);
    yaml_parser_delete(&parser);
    fclose(fp);

    return rc == 0 ? 0 : -1;
}
