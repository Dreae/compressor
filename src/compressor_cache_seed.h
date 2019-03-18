#pragma once

#include "config.h"

void start_seed_thread(struct forwarding_rule *rule, int cache_map_fd);
void start_cache_seeding(int cache_map_fd, struct forwarding_rule **rules);
