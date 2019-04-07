// Copyright (C) 2019 dreae
// 
// This file is part of compressor.
// 
// compressor is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// compressor is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with compressor.  If not, see <http://www.gnu.org/licenses/>.

#pragma once

#include "compressor.h"
#include "config.h"

#define MAX_CPUS 128
#define LRU_SIZE 16384

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

struct compressor_maps *load_xdp_prog(struct service_def **services, struct forwarding_rule **forwarding, struct config *cfg);
