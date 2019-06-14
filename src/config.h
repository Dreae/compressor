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

#include <stdint.h>
#include <libconfig.h>
#include <linux/in.h>
#include <stdlib.h>

struct config {
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

struct forwarding_rule *parse_forwarding_rule(config_setting_t *cfg_rule);

static inline void free_array(void **array) {
    void *elem;
    int idx = 0;
    while ((elem = array[idx]) != NULL) {
        free(elem);
        idx++;
    }

    free(array);
}
