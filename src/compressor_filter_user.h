#pragma once

#include "compressor.h"
#include "config.h"

struct compressor_maps {
    int xsk_map_fd;
    int rate_limit_map_fd;
    int new_conn_map_fd;
    int a2s_cache_map_fd;
};

struct lpm_trie_key {
    uint32_t prefixlen;
    uint32_t data;
};

extern int ifindex;

struct compressor_maps *load_xdp_prog(struct service_def **services, struct forwarding_rule **forwarding, struct in_addr **whitelisted_ips, struct whitelisted_prefix **whitelisted_prefixes, struct config *cfg);
