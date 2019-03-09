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
static int (*bpf_xdp_adjust_head)(void *ctx, int offset) = (void *) BPF_FUNC_xdp_adjust_head;
static int64_t (*bpf_csum_diff)(__be32 *from, uint32_t from_size, __be32 *to, uint32_t to_size, __wsum seed) = (void *) BPF_FUNC_csum_diff;
static uint64_t (*bpf_ktime_get_ns)(void) = (void *) BPF_FUNC_ktime_get_ns;
static int (*bpf_redirect_map)(void *map, int key, int flags) = (void *) BPF_FUNC_redirect_map;