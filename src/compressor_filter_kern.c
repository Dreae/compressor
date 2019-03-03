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
#define htons(x) ((__be16)___constant_swab16((x)))
#define htonl(x) ((__be32)___constant_swab32((x)))
static void *(*bpf_map_lookup_elem)(void *map, void *key) = (void *) BPF_FUNC_map_lookup_elem;

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
    .max_entries = 255
};

struct bpf_map_def SEC("maps") gateway_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(struct forwarding_rule),
    .max_entries = 255
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

SEC("xdp_prog")
int xdp_program(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    uint64_t nh_off = sizeof(*eth);
    if (data + nh_off > data_end) {
        return XDP_PASS;
    }

    struct config *cfg;
    uint32_t key = 0;
    cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!cfg) {
        return XDP_ABORTED;
    }

    uint16_t h_proto = eth->h_proto;
    for (int i = 0; i < 2; i++) {
        if (__builtin_expect(h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD), 0)) {
            struct vlan_hdr *vhdr;

            vhdr = data + nh_off;
            nh_off += sizeof(struct vlan_hdr);
            if (data + nh_off > data_end) {
                return XDP_PASS;
            }
            h_proto = vhdr->h_vlan_encapsulated_proto;
        }
    }

    if (__builtin_expect(h_proto == htons(ETH_P_IP), 1)) {
        struct iphdr *iph = data + nh_off;
        if(iph + 1 > (struct iphdr *)data_end) {
            return XDP_PASS;
        }

        uint8_t *value = bpf_map_lookup_elem(&blocked_ips, &iph->saddr);
        if (value && *value) {
            return XDP_DROP;
        }

        if (iph->protocol == IPPROTO_UDP) {
            struct udphdr *udph = data + nh_off + sizeof(struct iphdr);
            if (udph + 1 > (struct udphdr *)data_end) {
                return XDP_PASS;
            }

            struct forwarding_rule *rule;
            rule = bpf_map_lookup_elem(&forwarding_map, &iph->daddr);
            if (rule && rule->bind_port == htons(udph->dest)) {
                iph->daddr = rule->to_addr;
                udph->dest = rule->to_port;
                swap_dest_src_hwaddr(data);

                return XDP_TX;
            }
            rule = bpf_map_lookup_elem(&gateway_map, &iph->saddr);
            if (rule && rule->to_port == htons(udph->source)) {
                iph->saddr = rule->bind_addr;
                udph->source = rule->bind_port;
                swap_dest_src_hwaddr(data);

                return XDP_TX;
            } 
            
            uint32_t dest = (uint32_t)htons(udph->dest);
            value = bpf_map_lookup_elem(&udp_services, &dest);
            if (value && *value == 0) {
                return XDP_DROP;
            }
        } else if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *tcph = data + nh_off + sizeof(struct iphdr);
            if (tcph + 1 > (struct tcphdr *)data_end) {
                return XDP_PASS;
            }

            uint32_t dest = (uint32_t)htons(tcph->dest);
            value = bpf_map_lookup_elem(&tcp_services, &dest);
            if (value && *value == 0) {
                return XDP_DROP;
            }
        }
    }

    return XDP_PASS;
}