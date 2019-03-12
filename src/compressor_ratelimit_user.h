#pragma once

#include <stdint.h>

struct ip_addr_history {
    uint_fast64_t last_seen;
    uint_fast64_t hits;
};

void start_rlimit_mon(int rate_limit_map_fd, int new_ip_map_fd);