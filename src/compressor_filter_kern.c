#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/bpf_common.h>
#include <stdint.h>

#include "config.h"

#define SEC(NAME) __attribute__((section(NAME), used))

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
static int (*bpf_map_update_elem)(void *map, void *key, const void *value, uint64_t flags) = (void *) BPF_FUNC_map_update_elem;

struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

struct bpf_map_def {
      unsigned int type;
      unsigned int key_size;
      unsigned int value_size;
      unsigned int max_entries;
      unsigned int map_flags;
};

struct bpf_map_def SEC("maps") blocked_ips = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint8_t),
    .max_entries = 1000000,
};

struct bpf_map_def SEC("maps") tcp_services = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint8_t),
    .max_entries = 65536
};

struct bpf_map_def SEC("maps") udp_services = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint8_t),
    .max_entries = 65536
};

struct bpf_map_def SEC("maps") config_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(struct config),
    .max_entries = 1
};

struct bpf_map_def SEC("maps") forwarding_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(struct forwarding_rule),
    .max_entries = 256
};

struct bpf_map_def SEC("maps") tunnel_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(struct forwarding_rule),
    .max_entries = 256
};

static __always_inline void swap_dest_src_hwaddr(void *data) {
    uint16_t *p = data;
    uint16_t dst[3];

    dst[0] = p[0];
    dst[1] = p[1];
    dst[2] = p[2];
    p[0] = p[3];
    p[1] = p[4];
    p[2] = p[5];
    p[3] = dst[0];
    p[4] = dst[1];
    p[5] = dst[2];
}

static __always_inline void update_iph_checksum(struct iphdr *iph) {
    uint16_t *next_iph_u16 = (uint16_t *)iph;
    uint32_t csum = 0;
    iph->check = 0;
#pragma clang loop unroll(full)
    for (uint32_t i = 0; i < sizeof(*iph) >> 1; i++) {
        csum += *next_iph_u16++;
    }

    iph->check = ~((csum & 0xffff) + (csum >> 16));
}

static __always_inline void update_udph_checksum(struct iphdr *iph, struct udphdr *udph, void *data_end) {
    // TODO
    udph->check = 0;
}

SEC("xdp_prog")
int xdp_program(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if (eth + 1 > (struct ethhdr *)data_end) {
        return XDP_PASS;
    }

    struct config *cfg;
    uint32_t key = 0;
    cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!cfg) {
        return XDP_ABORTED;
    }

    if (__builtin_expect(eth->h_proto == htons(ETH_P_IP), 1)) {
        struct iphdr *iph = data + sizeof(struct ethhdr);
        if(iph + 1 > (struct iphdr *)data_end) {
            return XDP_PASS;
        }

        uint8_t *value = bpf_map_lookup_elem(&blocked_ips, &iph->saddr);
        if (value && *value) {
            return XDP_DROP;
        }

        if (iph->protocol == IPPROTO_UDP) {
            struct udphdr *udph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
            if (udph + 1 > (struct udphdr *)data_end) {
                return XDP_PASS;
            }

            struct forwarding_rule *rule;
            rule = bpf_map_lookup_elem(&forwarding_map, &iph->daddr);
            if (rule) {
                // Rule found, add outer IP frame
                if (bpf_xdp_adjust_head(ctx, 0 - (int)sizeof(struct iphdr))) {
                    return XDP_ABORTED;
                }

                data_end = (void *)(long)ctx->data_end;
                data = (void *)(long)ctx->data;
                struct ethhdr *new_eth = data;
                struct iphdr *new_iph = data + sizeof(struct ethhdr);
                struct ethhdr *old_eth = data + sizeof(struct iphdr);
                iph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
                if (new_eth + 1 > (struct ethhdr *)data_end || old_eth + 1 > (struct ethhdr *)data_end || new_iph + 1 > (struct iphdr *)data_end || iph + 1 > (struct iphdr *)data_end) {
                    return XDP_DROP;
                }

                // Ethernet header and IP header are the same size,
                // move the Ethernet header to the front of the newly
                // created space and add a new IP header in its place
                __builtin_memcpy(new_eth, old_eth, sizeof(struct ethhdr));
                new_iph->version = 4;
                new_iph->ihl = sizeof(struct iphdr) >> 2;
                new_iph->frag_off = 0;
                new_iph->protocol = IPPROTO_IPIP;
                new_iph->check = 0;
                new_iph->ttl = 64;
                new_iph->tos = 0;
                new_iph->tot_len = htons(ntohs(iph->tot_len) + sizeof(struct iphdr));
                new_iph->daddr = rule->to_addr;
                new_iph->saddr = rule->source_addr;
                update_iph_checksum(new_iph);

                iph->daddr = rule->to_addr;
                update_iph_checksum(iph);

                udph = data + sizeof(struct ethhdr) + (2 * sizeof(struct iphdr));
                if (udph + 1 > (struct udphdr *)data_end) {
                    return XDP_DROP;
                }
                // Do port translation only if we know what the port is doing
                if (ntohs(udph->dest) == rule->bind_port && rule->bind_port != rule->to_port) {
                    udph->dest = htons(rule->to_port);
                }
                update_udph_checksum(iph, udph, data_end);

                swap_dest_src_hwaddr(data);

                return XDP_TX;
            }

            uint32_t dest = (uint32_t)htons(udph->dest);
            value = bpf_map_lookup_elem(&udp_services, &dest);
            if (value && *value == 0) {
                return XDP_DROP;
            }
        } else if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
            if (tcph + 1 > (struct tcphdr *)data_end) {
                return XDP_PASS;
            }

            uint32_t dest = (uint32_t)htons(tcph->dest);
            value = bpf_map_lookup_elem(&tcp_services, &dest);
            if (value && *value == 0) {
                return XDP_DROP;
            }
        } else if (iph->protocol == IPPROTO_IPIP) {
            uint32_t saddr = iph->saddr;
            struct forwarding_rule *rule = bpf_map_lookup_elem(&tunnel_map, &saddr);
            if (!rule) {
                return XDP_DROP;
            }

            // Save a copy of the eth header since it will
            // get dropped when we move the XDP data
            struct ethhdr old_eth;
            __builtin_memcpy(&old_eth, eth, sizeof(struct ethhdr));

            // Remove outer IP frame
            if (bpf_xdp_adjust_head(ctx, (int)sizeof(struct iphdr))) {
                return XDP_DROP;
            }
            data = (void *)(long)ctx->data;
            data_end = (void *)(long)ctx->data_end;
            struct ethhdr *new_eth = data;
            struct iphdr *inner_ip = data + sizeof(struct ethhdr);

            if (new_eth + 1 > (struct ethhdr *)data_end || inner_ip + 1 > (struct iphdr *)data_end) {
                return XDP_DROP;
            }
            __builtin_memcpy(new_eth, &old_eth, sizeof(struct ethhdr));
            swap_dest_src_hwaddr(data);

            inner_ip->saddr = rule->bind_addr;
            update_iph_checksum(inner_ip);

            if (inner_ip->protocol == IPPROTO_UDP) {
                struct udphdr *udph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
                if (udph + 1 > (struct udphdr *)data_end) {
                    return XDP_DROP;
                }

                if (ntohs(udph->source) == rule->to_port && ntohs(udph->source) != rule->bind_port) {
                    udph->source = htons(rule->bind_port);
                }
                update_udph_checksum(inner_ip, udph, data_end);
            }

            return XDP_TX;
        }
    }

    return XDP_PASS;
}