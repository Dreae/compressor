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

#include "bpf_kern_common.h"
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/bpf_common.h>
#include <linux/icmp.h>
#include <stdint.h>
#include <stdatomic.h>

#include "config.h"
#include "compressor_cache_user.h"
#include "srcds_util.h"
#include "compressor_filter_user.h"
#include "checksum.h"

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
struct bpf_map_def SEC("maps") config_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(struct config),
    .max_entries = 1
};

// Map 1
struct bpf_map_def SEC("maps") forwarding_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(struct forwarding_rule),
    .max_entries = 256
};

// Keyed by (dest_ip << 32) | internal_ip to support
// multiple internal IPs on the same host
// Map 2
struct bpf_map_def SEC("maps") tunnel_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint64_t),
    .value_size = sizeof(struct forwarding_rule),
    .max_entries = 256
};

// Map 3
struct bpf_map_def SEC("maps") xsk_map = {
    .type = BPF_MAP_TYPE_XSKMAP,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint32_t),
    .max_entries = MAX_CPUS
};

// Map 4
struct bpf_map_def SEC("maps") a2s_info_cache_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(struct a2s_info_cache_entry),
    .max_entries = 255
};

// Map 5
struct bpf_map_def SEC("maps") rate_limit_inner_map = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(struct ip_addr_history),
    .max_entries = LRU_SIZE
};

// Map 6
struct bpf_map_def SEC("maps") rate_limit_map = {
    .type = BPF_MAP_TYPE_ARRAY_OF_MAPS,
    .key_size = sizeof(uint32_t),
    .max_entries = MAX_CPUS,
    .inner_map_idx = 5
};

// Map 7
struct bpf_map_def SEC("maps") new_conn_map = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(struct compressor_new_ips),
    .max_entries = 1
};

// Map 8
struct bpf_map_def SEC("maps") stats_map = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(struct compressor_stats),
    .max_entries = 1
};

static __always_inline void copy_and_swap_hwaddr(struct ethhdr *new_hdr, struct ethhdr *old_hdr) {
    uint16_t *new_p = (uint16_t *)new_hdr;
    uint16_t *old_p = (uint16_t *)old_hdr;

    new_p[0] = old_p[3];
    new_p[1] = old_p[4];
    new_p[2] = old_p[5];
    new_p[3] = old_p[0];
    new_p[4] = old_p[1];
    new_p[5] = old_p[2];
    new_hdr->h_proto = old_hdr->h_proto;
}

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
        copy_and_swap_hwaddr(new_eth, old_eth);
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

    struct compressor_stats *stats = bpf_map_lookup_elem(&stats_map, &key);
    if (stats) {
        stats->packet_count++;
    }

    if (likely(eth->h_proto == htons(ETH_P_IP))) {
        struct iphdr *iph = data + sizeof(struct ethhdr);
        if(unlikely(iph + 1 > (struct iphdr *)data_end)) {
            return XDP_DROP;
        }

        if (
            unlikely(
                iph->protocol != IPPROTO_UDP &&
                iph->protocol != IPPROTO_TCP &&
                iph->protocol != IPPROTO_IPIP &&
                iph->protocol != IPPROTO_ICMP
            )
        ) {
            return XDP_DROP;
        }

        if (iph->protocol == IPPROTO_IPIP) {
            struct iphdr *inner_ip = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
            if (inner_ip + 1 > (struct iphdr *)data_end) {
                return XDP_ABORTED;
            }

            uint64_t key = ((uint64_t)iph->saddr << 32) | inner_ip->saddr;
            struct forwarding_rule *tunnel_rule = bpf_map_lookup_elem(&tunnel_map, &key);
            if (!tunnel_rule) {
                return XDP_DROP;
            }

            struct ethhdr *new_eth = data + sizeof(struct iphdr);
            copy_and_swap_hwaddr(new_eth, eth);

            // Remove outer IP frame
            if (bpf_xdp_adjust_head(ctx, (int)sizeof(struct iphdr))) {
                return XDP_DROP;
            }
            data = (void *)(long)ctx->data;
            data_end = (void *)(long)ctx->data_end;
            inner_ip = data + sizeof(struct ethhdr);

            if (inner_ip + 1 > (struct iphdr *)data_end) {
                return XDP_DROP;
            }

            uint32_t old_saddr = inner_ip->saddr;
            inner_ip->saddr = tunnel_rule->bind_addr;
            inner_ip->check = csum_diff4(old_saddr, inner_ip->saddr, inner_ip->check);

            if (inner_ip->protocol == IPPROTO_UDP) {
                struct udphdr *udph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
                if (udph + 1 > (struct udphdr *)data_end) {
                    return XDP_DROP;
                }

                udph->check = csum_diff4(old_saddr, inner_ip->saddr, udph->check);

                if (ntohs(udph->source) == tunnel_rule->to_port) {
                    uint16_t old_tos = *((uint16_t *)inner_ip);
                    inner_ip->tos = 0x50;
                    inner_ip->check = csum_diff4(old_tos, *((uint16_t *)inner_ip), inner_ip->check);

                    if (ntohs(udph->source) != tunnel_rule->bind_port) {
                        uint32_t source = udph->source;
                        uint32_t dest = ntohs(tunnel_rule->bind_port);
                        udph->source = dest;
                        udph->check = csum_diff4(source, dest, udph->check);
                    }

                    uint8_t *udpdata = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
                    if (!(udpdata + 5 > (uint8_t *)data_end)) {
                        if (check_srcds_header(udpdata, 0x49) && tunnel_rule->a2s_info_cache) {
                            return bpf_redirect_map(&xsk_map, bpf_get_smp_processor_id(), 0);
                        }
                    }
                }

            } else if (inner_ip->protocol == IPPROTO_TCP) {
                struct tcphdr *tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
                if (tcph + 1 > (struct tcphdr *)data_end) {
                    return XDP_ABORTED;
                }

                tcph->check = csum_diff4(old_saddr, inner_ip->saddr, tcph->check);
            }

            return XDP_TX;
        } else {
            uint32_t cpu_id = bpf_get_smp_processor_id();
            void *lru_map = bpf_map_lookup_elem(&rate_limit_map, &cpu_id);
            if (unlikely(lru_map == NULL)) {
                // How?
                return XDP_ABORTED;
            }

            // Check for TCP exclude.
            if (cfg->tcp_exclude == 1 && iph->protocol == IPPROTO_TCP)
            {
                struct tcphdr *tcph = (data + sizeof(struct ethhdr) + (iph->ihl * 4));

                if (tcph + 1 > (struct tcphdr *)data_end)
                {
                    return XDP_DROP;
                }

                // Check to make sure SYN flag isn't set so we exclude SYN-related attacks.
                if (tcph->syn == 0)
                {
                    goto endratelimit;
                }
            }

            struct ip_addr_history *last_seen = bpf_map_lookup_elem(lru_map, &iph->saddr);
            uint64_t now = bpf_ktime_get_ns();
            if (!last_seen) {

                uint32_t key = 0;
                struct compressor_new_ips *new_ip_stats = bpf_map_lookup_elem(&new_conn_map, &key);
                if (!new_ip_stats) {
                    return XDP_ABORTED;
                }

                if (now - new_ip_stats->timestamp > 1e9) {
                    new_ip_stats->new_ips = 1;
                    new_ip_stats->timestamp = now;
                } else {
                    new_ip_stats->new_ips += 1;
                    if (new_ip_stats->new_ips > cfg->new_conn_limit) {
                        return XDP_DROP;
                    }
                }

                struct ip_addr_history new_entry = {
                    .timestamp = now,
                    .hits = 1
                };
                bpf_map_update_elem(lru_map, &iph->saddr, &new_entry, BPF_ANY);
            } else {
                if (now - last_seen->timestamp > 6e10) {
                    last_seen->hits = 1;
                    last_seen->timestamp = now;
                } else {
                    last_seen->hits += 1;
                }

                if (last_seen->hits > cfg->rate_limit) {
                    return XDP_DROP;
                }
            }

            endratelimit:

            if (iph->protocol == IPPROTO_UDP) {
                struct udphdr *udph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
                if (udph + 1 > (struct udphdr *)data_end) {
                    return XDP_PASS;
                }
                struct forwarding_rule *forward_rule = bpf_map_lookup_elem(&forwarding_map, &iph->daddr);

                uint32_t dest = (uint32_t)ntohs(udph->dest);
                if (forward_rule) {
                    // Drop zero length packets
                    // See https://wiki.alliedmods.net/SRCDS_Hardening#Force_fullupdate
                    if (udph->len == 0) {
                        return XDP_DROP;
                    }

                    const uint8_t *udp_bytes = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
                    if (dest == forward_rule->bind_port) {
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
                                        __sync_fetch_and_add(&entry->hits, 1);

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

                                        return bpf_redirect_map(&xsk_map, bpf_get_smp_processor_id(), 0);
                                    }

                                    __sync_fetch_and_add(&entry->misses, 1);
                                }
                            }
                        }

                        // Do port translation only if we know what the port is doing
                        if (forward_rule->bind_port != forward_rule->to_port) {
                            uint32_t old_dest = udph->dest;
                            uint32_t new_dest = htons(forward_rule->to_port);
                            udph->dest = new_dest;
                            udph->check = csum_diff4(old_dest, new_dest, udph->check);
                        }
                    }


                    uint32_t daddr = iph->daddr;
                    iph->daddr = forward_rule->inner_addr;
                    iph->check = csum_diff4(daddr, iph->daddr, iph->check);
                    udph->check = csum_diff4(daddr, iph->daddr, udph->check);

                    return forward_packet(ctx, forward_rule, 0x50);
                }

                return XDP_PASS;
            } else if (iph->protocol == IPPROTO_TCP) {
                struct tcphdr *tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
                if (tcph + 1 > (struct tcphdr *)data_end) {
                    return XDP_DROP;
                }

                if (tcph->dest == htons(22)) {
                    return XDP_PASS;
                }

                struct forwarding_rule *forward_rule = bpf_map_lookup_elem(&forwarding_map, &iph->daddr);
                if (forward_rule) {
                    uint32_t daddr = iph->daddr;
                    iph->daddr = forward_rule->inner_addr;
                    iph->check = csum_diff4(daddr, iph->daddr, iph->check);
                    tcph->check = csum_diff4(daddr, iph->daddr, tcph->check);

                    return forward_packet(ctx, forward_rule, 0x00);
                }

                return XDP_PASS;
            } else if (iph->protocol == IPPROTO_ICMP) {
                struct icmphdr *icmph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
                if (icmph + 1 > (struct icmphdr *)data_end) {
                    return XDP_ABORTED;
                }

                struct forwarding_rule *forward_rule = bpf_map_lookup_elem(&forwarding_map, &iph->daddr);
                if (forward_rule) {
                    uint32_t daddr = iph->daddr;
                    iph->daddr = forward_rule->inner_addr;
                    iph->check = csum_diff4(daddr, iph->daddr, iph->check);

                    return forward_packet(ctx, forward_rule, 0x00);
                }

                return XDP_PASS;
            }
        }


        return XDP_DROP;
    } else if (eth->h_proto == ETH_P_IPV6) {
        return XDP_DROP;
    }

    // Allow other ether protocols, like ARP
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
