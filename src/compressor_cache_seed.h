#pragma once

#include "config.h"

void start_cache_seeding(int cache_map_fd, struct forwarding_rule **rules, uint32_t redis_addr, uint16_t redis_port);
