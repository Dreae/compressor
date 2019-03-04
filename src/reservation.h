#pragma once

#include <stdint.h>

struct port_reservation {
    uint16_t bind_port;
    uint32_t remote_addr;
    uint16_t remote_port;
    uint8_t age;
    uint8_t credits;
};

struct reverse_port_mapping {
    uint64_t reservation;
};

__always_inline uint64_t ip_port_to_key(uint32_t ip, uint16_t port) {
    return (((uint64_t)ip) << 32) | (((uint64_t)port) << 16);
}
