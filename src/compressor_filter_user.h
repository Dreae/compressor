#pragma once

#include "compressor.h"
#include "config.h"

#define MAX_CPUS 128
#define LRU_SIZE 65535

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

struct compressor_new_ips {
    uint_fast64_t new_ips;
    uint_fast64_t timestamp;
};

struct ip_addr_history {
    uint_fast64_t timestamp;
    uint_fast64_t hits;
};

extern int ifindex;

struct compressor_maps *load_xdp_prog(struct service_def **services, struct forwarding_rule **forwarding, struct in_addr **whitelisted_ips, struct whitelisted_prefix **whitelisted_prefixes, struct config *cfg);
