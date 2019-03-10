#include "bpf_kern_common.h"
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/bpf_common.h>
#include <stdint.h>
#include <stdatomic.h>

#include "config.h"
#include "compressor_cache_user.h"
#include "srcds_util.h"

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
    unsigned int inner_map_idx;
    unsigned int numa_node;
};

// Map 0
struct bpf_map_def SEC("maps") tcp_services = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint8_t),
    .max_entries = 65536
};

// Map 1
struct bpf_map_def SEC("maps") udp_services = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint8_t),
    .max_entries = 65536
};

// Map 2
struct bpf_map_def SEC("maps") config_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(struct config),
    .max_entries = 1
};

// Map 3
struct bpf_map_def SEC("maps") forwarding_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(struct forwarding_rule),
    .max_entries = 256
};

// Map 4
struct bpf_map_def SEC("maps") tunnel_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(struct forwarding_rule),
    .max_entries = 256
};

// Map 5
struct bpf_map_def SEC("maps") xsk_map = {
    .type = BPF_MAP_TYPE_XSKMAP,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint32_t),
    .max_entries = 4
};

struct bpf_map_def SEC("maps") a2s_info_cache_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(struct a2s_info_cache_entry),
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
    // FIXME: calculate new UDP checksum
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

    if (likely(eth->h_proto == htons(ETH_P_IP))) {
        struct iphdr *iph = data + sizeof(struct ethhdr);
        if(iph + 1 > (struct iphdr *)data_end) {
            return XDP_PASS;
        }

        if (iph->protocol == IPPROTO_UDP) {
            struct udphdr *udph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
            if (udph + 1 > (struct udphdr *)data_end) {
                return XDP_PASS;
            }

            uint32_t dest = (uint32_t)ntohs(udph->dest);
            struct forwarding_rule *rule = bpf_map_lookup_elem(&forwarding_map, &iph->daddr);
            if (rule) {
                if (udph->dest != htons(rule->bind_port) && udph->dest != htons(rule->steam_port) && iph->saddr != 0x08080808) {
                    return XDP_DROP;
                }

                // Drop zero length packets
                // See https://wiki.alliedmods.net/SRCDS_Hardening#Force_fullupdate
                if (udph->len == 0) {
                    return XDP_DROP;
                }

                const uint8_t *udp_bytes = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
                if (!(udp_bytes + 5 > (uint8_t *)data_end)) {
                    // Drop A2C_PRINT
                    // See https://wiki.alliedmods.net/SRCDS_Hardening#A2C_PRINT_Spam
                    if (check_srcds_header(udp_bytes, 0x6c)) {
                        return XDP_DROP;
                    }

                    if (check_srcds_header(udp_bytes, 0x54) && rule->a2s_info_cache) {
                        struct a2s_info_cache_entry *entry = bpf_map_lookup_elem(&a2s_info_cache_map, &iph->daddr);
                        if (entry) {
                            if ((entry->misses > rule->a2s_info_cache || rule->a2s_info_cache == 1) && bpf_ktime_get_ns() - entry->age < rule->cache_time) {
                                // Set up address so all userspace needs to do is fill out the
                                // data and retransmit
                                uint32_t saddr = iph->saddr;
                                iph->saddr = iph->daddr;
                                iph->daddr = saddr;
                                uint16_t dest = udph->dest;
                                udph->dest = udph->source;
                                udph->source = dest;

                                // We don't need to update checksums, since userspace will need to
                                // either way

                                swap_dest_src_hwaddr(data);

                                return bpf_redirect_map(&xsk_map, 0, 0);
                            }
                            
                            entry->misses++;
                        }
                    }
                }

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
                new_iph->saddr = rule->bind_addr;
                update_iph_checksum(new_iph);

                iph->daddr = rule->to_addr;
                update_iph_checksum(iph);

                udph = data + sizeof(struct ethhdr) + (2 * sizeof(struct iphdr));
                if (udph + 1 > (struct udphdr *)data_end) {
                    return XDP_DROP;
                }
                // Do port translation only if we know what the port is doing
                if (dest == rule->bind_port && rule->bind_port != rule->to_port) {
                    udph->dest = htons(rule->to_port);
                }
                update_udph_checksum(iph, udph, data_end);

                swap_dest_src_hwaddr(data);

                return XDP_TX;
            }

            uint8_t *value = bpf_map_lookup_elem(&udp_services, &dest);
            if (value && *value == 0) {
                return XDP_DROP;
            }
        } else if (iph->protocol == IPPROTO_TCP) {
            if (iph->saddr == cfg->bgp_peer) {
                return XDP_PASS;
            }

            struct tcphdr *tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
            if (tcph + 1 > (struct tcphdr *)data_end) {
                return XDP_PASS;
            }

            uint32_t dest = (uint32_t)htons(tcph->dest);
            uint8_t *value = bpf_map_lookup_elem(&tcp_services, &dest);
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

                if (ntohs(udph->source) == rule->to_port) {
                    if (ntohs(udph->source) != rule->bind_port) {
                        udph->source = htons(rule->bind_port);
                    }

                    uint8_t *udpdata = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
                    if (!(udpdata + 5 > (uint8_t *)data_end)) {
                        if (check_srcds_header(udpdata, 0x49) && rule->a2s_info_cache) {
                            return bpf_redirect_map(&xsk_map, 0, 0);
                        }
                    }
                }

                update_udph_checksum(inner_ip, udph, data_end);
            }

            return XDP_TX;
        }
    }

    // FIXME: Figure out why default DROP kills SSH
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
