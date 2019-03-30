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

#include <linux/bpf.h>
#include <stdint.h>


#define SEC(NAME) __attribute__((section(NAME), used))
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define htons(x) ((__be16)___constant_swab16((x)))
#define ntohs(x) ((__be16)___constant_swab16((x)))
#define htonl(x) ((__be32)___constant_swab32((x)))
#define ntohl(x) ((__be32)___constant_swab32((x)))
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define htons(x) (x)
#define ntohs(X) (x)
#define htonl(x) (x)
#define ntohl(x) (x)
#endif

static void *(*bpf_map_lookup_elem)(void *map, void *key) = (void *) BPF_FUNC_map_lookup_elem;
static int (*bpf_map_update_elem)(void *map, const void *key, const void *value, uint64_t flags) = (void *) BPF_FUNC_map_update_elem;
static int (*bpf_xdp_adjust_head)(void *ctx, int offset) = (void *) BPF_FUNC_xdp_adjust_head;
static int64_t (*bpf_csum_diff)(__be32 *from, uint32_t from_size, __be32 *to, uint32_t to_size, __wsum seed) = (void *) BPF_FUNC_csum_diff;
static uint64_t (*bpf_ktime_get_ns)(void) = (void *) BPF_FUNC_ktime_get_ns;
static int (*bpf_redirect_map)(void *map, int key, int flags) = (void *) BPF_FUNC_redirect_map;
static uint32_t (*bpf_get_smp_processor_id)(void) = (void *) BPF_FUNC_get_smp_processor_id;