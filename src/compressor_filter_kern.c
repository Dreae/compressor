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
#include "compressor_ratelimit_user.h"
#include "srcds_util.h"
#include "compressor_filter_user.h"

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

// Keyed by (dest_ip << 32) | internal_ip to support
// multiple internal IPs on the same host
// Map 4
struct bpf_map_def SEC("maps") tunnel_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint64_t),
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

// Map 6
struct bpf_map_def SEC("maps") a2s_info_cache_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(struct a2s_info_cache_entry),
    .max_entries = 255
};

// Map 7
struct bpf_map_def SEC("maps") rate_limit_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(struct ip_addr_history),
    .max_entries = 1048560
};

// Map 8
struct bpf_map_def SEC("maps") new_conn_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint_fast64_t),
    .max_entries = 1
};

// Map 9
struct bpf_map_def SEC("maps") ip_whitelist_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint8_t),
    .max_entries = 4096
};

// Reserved for a list of dest IPs to exclude game server hosts
// from rate limiting
// Map 10
struct bpf_map_def SEC("maps") known_hosts = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint8_t),
    .max_entries = 256
};

// Map 11
struct bpf_map_def SEC("maps") ip_prefix_whitelist_map = {
    .type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(struct lpm_trie_key),
    .value_size = sizeof(uint64_t),
    .max_entries = 16384,
    .map_flags = BPF_F_NO_PREALLOC
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

static __always_inline uint16_t csum_fold_helper(uint32_t csum) {
    uint32_t r = csum << 16 | csum >> 16;
    csum = ~csum;
    csum -= r;
    return (uint16_t)(csum >> 16);
}

static __always_inline uint32_t csum_add(uint32_t addend, uint32_t csum) {
    uint32_t res = csum;
    res += addend;
    return (res + (res < addend));
}

static __always_inline uint32_t csum_sub(uint32_t addend, uint32_t csum) {
    return csum_add(csum, ~addend);
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

static __always_inline uint16_t csum_diff4(uint32_t from, uint32_t to, uint16_t csum) {
    uint32_t tmp = csum_sub(from, ~((uint32_t)csum));
    return csum_fold_helper(csum_add(to, tmp));
}

static __always_inline int forward_packet(struct xdp_md *ctx, struct forwarding_rule *rule, uint8_t tos) {
    // Rule found, add outer IP frame
        if (bpf_xdp_adjust_head(ctx, 0 - (int)sizeof(struct iphdr))) {
            return XDP_ABORTED;
        }

        void *data_end = (void *)(long)ctx->data_end;
        void *data = (void *)(long)ctx->data;
        struct ethhdr *new_eth = data;
        struct iphdr *new_iph = data + sizeof(struct ethhdr);
        struct ethhdr *old_eth = data + sizeof(struct iphdr);
        struct iphdr *iph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
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
        new_iph->tos = tos;
        new_iph->tot_len = htons(ntohs(iph->tot_len) + sizeof(struct iphdr));
        new_iph->daddr = rule->to_addr;
        new_iph->saddr = rule->bind_addr;
        update_iph_checksum(new_iph);

        swap_dest_src_hwaddr(data);

        return XDP_TX;
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
        if(unlikely(iph + 1 > (struct iphdr *)data_end)) {
            return XDP_DROP;
        }

        uint8_t *whitelist_entry = bpf_map_lookup_elem(&ip_whitelist_map, &iph->saddr);
        uint8_t ip_whitelisted = 0;
        if (whitelist_entry) {
            ip_whitelisted = *whitelist_entry;
        } else {
            struct lpm_trie_key key;
            key.prefixlen = 32;
            key.data = iph->saddr;
            uint64_t *prefix_mask = bpf_map_lookup_elem(&ip_prefix_whitelist_map, &key);
            if (prefix_mask) {
                uint32_t bitmask = (*prefix_mask) >> 32;
                uint32_t prefix = (*prefix_mask) & 0xffffffff;
                if ((iph->saddr & bitmask) == prefix) {
                    ip_whitelisted = 1;
                }
            }
        }

        uint8_t *known_host = bpf_map_lookup_elem(&known_hosts, &iph->saddr);
        if (!known_host || !(*known_host)) {
            struct ip_addr_history *last_seen = bpf_map_lookup_elem(&rate_limit_map, &iph->saddr);
            uint64_t now = bpf_ktime_get_ns();
            if (!last_seen) {

                uint32_t key = 0;
                uint_fast64_t *new_ips = bpf_map_lookup_elem(&new_conn_map, &key);
                if (!new_ips) {
                    return XDP_ABORTED;
                }

                *new_ips = *new_ips + 1;
                if (*new_ips > cfg->new_conn_limit) {
                    return XDP_DROP;
                }

                struct ip_addr_history new_entry = {
                    .last_seen = now,
                    .hits = 1
                };
                bpf_map_update_elem(&rate_limit_map, &iph->saddr, &new_entry, BPF_ANY);
            } else {
                last_seen->last_seen = now;
                last_seen->hits++;

                if (last_seen->hits > cfg->rate_limit) {
                    return XDP_DROP;
                }
            }
        }

        if (iph->protocol == IPPROTO_UDP) {
            struct forwarding_rule *forward_rule = bpf_map_lookup_elem(&forwarding_map, &iph->daddr);
            struct udphdr *udph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
            if (udph + 1 > (struct udphdr *)data_end) {
                return XDP_PASS;
            }

            uint32_t dest = (uint32_t)ntohs(udph->dest);
            if (forward_rule) {
                if (udph->dest != htons(forward_rule->bind_port) && udph->dest != htons(forward_rule->steam_port) && !ip_whitelisted) {
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

                    if (check_srcds_header(udp_bytes, 0x54) && forward_rule->a2s_info_cache) {
                        struct a2s_info_cache_entry *entry = bpf_map_lookup_elem(&a2s_info_cache_map, &iph->daddr);
                        if (entry) {
                            if ((entry->misses > forward_rule->a2s_info_cache || forward_rule->a2s_info_cache == 1) && bpf_ktime_get_ns() - entry->age < forward_rule->cache_time) {
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

                // Do port translation only if we know what the port is doing
                if (dest == forward_rule->bind_port && forward_rule->bind_port != forward_rule->to_port) {
                    uint32_t old_dest = udph->dest;
                    uint32_t new_dest = htons(forward_rule->to_port);
                    udph->dest = new_dest;
                    udph->check = csum_diff4(old_dest, new_dest, udph->check);
                }

                uint32_t daddr = iph->daddr;
                iph->daddr = forward_rule->inner_addr;
                update_iph_checksum(iph);
                udph->check = csum_diff4(daddr, iph->daddr, udph->check);

                return forward_packet(ctx, forward_rule, 0x50);
            }

            if (ip_whitelisted) {
                return XDP_PASS;
            } else {
                uint8_t *value = bpf_map_lookup_elem(&udp_services, &dest);
                if (value && *value == 1) {
                    return XDP_PASS;
                }
            }

            return XDP_DROP;
        } else if (iph->protocol == IPPROTO_TCP) {
            struct forwarding_rule *forward_rule = bpf_map_lookup_elem(&forwarding_map, &iph->daddr);
            struct tcphdr *tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
            if (tcph + 1 > (struct tcphdr *)data_end) {
                return XDP_DROP;
            }

            if (forward_rule && ip_whitelisted) {
                uint32_t daddr = iph->daddr;
                iph->daddr = forward_rule->inner_addr;
                update_iph_checksum(iph);
                tcph->check = csum_diff4(daddr, iph->daddr, tcph->check);

                return forward_packet(ctx, forward_rule, 0x00);
            }

            if (ip_whitelisted) {
                return XDP_PASS;
            } else {
                uint32_t dest = (uint32_t)ntohs(tcph->dest);
                uint8_t *value = bpf_map_lookup_elem(&tcp_services, &dest);
                if (value && *value == 1) {
                    return XDP_PASS;
                }
            }

            return XDP_DROP;
        } else if (iph->protocol == IPPROTO_IPIP) {
            struct iphdr *inner_ip = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
            if (inner_ip + 1 > (struct iphdr *)data_end) {
                return XDP_ABORTED;
            }

            uint64_t key = ((uint64_t)iph->saddr << 32) | inner_ip->saddr;
            struct forwarding_rule *tunnel_rule = bpf_map_lookup_elem(&tunnel_map, &key);
            if (!tunnel_rule) {
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
            inner_ip = data + sizeof(struct ethhdr);

            if (new_eth + 1 > (struct ethhdr *)data_end || inner_ip + 1 > (struct iphdr *)data_end) {
                return XDP_DROP;
            }
            __builtin_memcpy(new_eth, &old_eth, sizeof(struct ethhdr));
            swap_dest_src_hwaddr(data);

            uint32_t old_saddr = inner_ip->saddr;
            inner_ip->saddr = tunnel_rule->bind_addr;

            if (inner_ip->protocol == IPPROTO_UDP) {
                struct udphdr *udph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
                if (udph + 1 > (struct udphdr *)data_end) {
                    return XDP_DROP;
                }

                if (ntohs(udph->source) == tunnel_rule->to_port) {
                    inner_ip->tos = 0x50;
                    uint8_t *udpdata = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
                    if (!(udpdata + 5 > (uint8_t *)data_end)) {
                        if (check_srcds_header(udpdata, 0x49) && tunnel_rule->a2s_info_cache) {
                            return bpf_redirect_map(&xsk_map, 0, 0);
                        }
                    }

                    if (ntohs(udph->source) != tunnel_rule->bind_port) {
                        uint32_t source = udph->source;
                        uint32_t dest = ntohs(tunnel_rule->bind_port);
                        udph->source = dest;
                        udph->check = csum_diff4(source, dest, udph->check);
                    }
                }

                udph->check = csum_diff4(old_saddr, inner_ip->saddr, udph->check);
            } else if (inner_ip->protocol == IPPROTO_TCP) {
                struct tcphdr *tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
                if (tcph + 1 > (struct tcphdr *)data_end) {
                    return XDP_ABORTED;
                }

                tcph->check = csum_diff4(old_saddr, inner_ip->saddr, tcph->check);
            }

            update_iph_checksum(inner_ip);
            return XDP_TX;
        }

        return XDP_DROP;
    } else if (eth->h_proto == ETH_P_IPV6) {
        return XDP_DROP;
    }

    // Allow other ether protocols, like ARP
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
