/**
 * Copyright (C) 2019 dreae
 *
 * This file is part of compressor.
 *
 * compressor is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * compressor is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with compressor.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include "compressor_filter_user.h"

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define htonll(x) ((__be64)___constant_swab64((x)))
#define ntohll(x) ((__be64)___constant_swab64((x)))
#else
#define htonll(x) (x)
#define ntohll(x) (x)
#endif

enum cockpit_command {
  NONE = 0,
  SERVER_UPDATE,
  CURRENT_PPS
};

void start_cockpit_port(struct compressor_maps *forwarding_map_fd);

struct server_update_msg {
  uint32_t bind_addr;
  uint16_t bind_port;
  uint32_t dest_addr;
  uint16_t dest_port;
  uint32_t internal_addr;
  uint32_t cache_time;
  uint32_t a2s_info_cache;
} __attribute__((packed));