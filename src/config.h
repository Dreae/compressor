#pragma once

#include <stdint.h>
#include <libconfig.h>

struct config {
    uint16_t hw1;
    uint16_t hw2;
    uint16_t hw3;
    uint32_t bgp_peer;
};

struct forwarding_rule {
    uint32_t bind_addr;
    uint16_t bind_port;
    uint32_t source_addr;
    uint16_t source_port;
    uint32_t to_addr;
    uint16_t to_port;
};

struct tunnel_port_lease {
    uint64_t time;
    uint32_t daddr;
};

struct service_def *parse_service(const char *service);
struct forwarding_rule *parse_forwarding_rule(config_setting_t *cfg_rule);