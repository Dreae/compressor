#pragma once

#include <stdint.h>
#include <libconfig.h>
#include <linux/in.h>
#include <stdlib.h>

struct config {
    uint16_t hw1;
    uint16_t hw2;
    uint16_t hw3;
    uint32_t bgp_peer;
    uint_fast64_t new_conn_limit;
    uint_fast64_t rate_limit;
};

struct forwarding_rule {
    uint32_t bind_addr;
    uint16_t bind_port;

    uint32_t to_addr;
    uint16_t to_port;
    uint16_t steam_port;
    uint32_t inner_addr;

    uint_fast32_t a2s_info_cache;
    uint_fast64_t cache_time;
};


struct service_def *parse_service(const char *service);
struct forwarding_rule *parse_forwarding_rule(config_setting_t *cfg_rule);
struct in_addr **parse_ip_whitelist(config_setting_t *whitelist);
void parse_asn_whitelist(config_setting_t *whitelist, struct in_addr ***ip_whitelist);

static inline void free_array(void **array) {
    void *elem;
    int idx = 0;
    while ((elem = array[idx]) != NULL) {
        free(elem);
        idx++;
    }

    free(array);
}