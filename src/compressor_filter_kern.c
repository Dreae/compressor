#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/bpf_common.h>
#include <stdint.h>
#include <stdlib.h>

#include "config.h"
#include "reservation.h"

#define SEC(NAME) __attribute__((section(NAME), used))
#define htons(x) ((__be16)___constant_swab16((x)))
#define htonl(x) ((__be32)___constant_swab32((x)))
static void *(*bpf_map_lookup_elem)(void *map, void *key) = (void *) BPF_FUNC_map_lookup_elem;
static void *(*bpf_map_update_elem)(void *map, void *key, void *value, int flags) BPF_FUNC_map_update_elem;

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
    .key_size = sizeof(uint64_t),
    .value_size = sizeof(struct forwarding_rule),
    .max_entries = 255
};

struct bpf_map_def SEC("maps") upd_port_reservation = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint64_t),
    .value_size = sizeof(struct port_reservation),
    .max_entries = 262140
};

struct bpf_map_def SEC("maps") reverse_port_reservation = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint64_t),
    .value_size = sizeof(struct reverse_port_mapping),
    .max_entries = 262140
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

static __always_inline struct port_reservation *generate_new_reservation(uint32_t sip, uint32_t ip, uint16_t port) {
    struct port_reservation *reservation;
    struct reverse_port_mapping *mapping;
    uint16_t sport;
    uint64_t key;

    for (sport = 1; sport < 65535; sport++) {
        key = ip_port_to_key(sip, sport);
        mapping = bpf_map_lookup_elem(&reverse_port_reservation, &key);
        if (!mapping) {
            break;
        }
    }

    reservation = malloc(sizeof(struct port_reservation));
    reservation->bind_port = sport;
    reservation->age = 0;
    reservation->credits = 200;
    reservation->remote_addr = ip;
    reservation->remote_port = port;

    mapping = malloc(sizeof(struct reverse_port_mapping));
    mapping->reservation = key;

    bpf_map_update_elem(&upd_port_reservation, &key, reservation, BPF_ANY);
    bpf_map_update_elem(&reverse_port_reservation, &key, mapping, BPF_ANY);

    return reservation;
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
            uint64_t key = ip_port_to_key(iph->daddr, htons(udph->dest));
            rule = bpf_map_lookup_elem(&forwarding_map, &key);
            if (rule) {
                key = ip_port_to_key(iph->saddr, htons(udph->source));
                struct port_reservation *existing_reservation;
                existing_reservation = bpf_map_lookup_elem(&upd_port_reservation, &key);
                if (existing_reservation) {
                    if (existing_reservation->credits <= 0) {
                        return XDP_DROP;
                    }
                } else {
                    existing_reservation = generate_new_reservation(rule->source_addr, iph->saddr, htons(udph->source));
                    if (!existing_reservation) {
                        return XDP_ABORTED;
                    }
                }
                udph->source = existing_reservation->bind_port;
                existing_reservation->credits--;
                existing_reservation->age = 0;

                iph->daddr = rule->to_addr;
                iph->saddr = rule->bind_addr;
                iph->ttl = 64;
                udph->dest = htons(rule->to_port);

                update_iph_checksum(iph);

                swap_dest_src_hwaddr(data);

                return XDP_TX;
            }

            key = ip_port_to_key(iph->saddr, htons(udph->source));
            rule = bpf_map_lookup_elem(&forwarding_map, &key);
            if (rule) {
                key = ip_port_to_key(iph->daddr, htons(udph->dest));
                struct reverse_port_mapping *mapping;
                mapping = bpf_map_lookup_elem(&reverse_port_reservation, &key);
                if (mapping) {
                    struct port_reservation *reservation;
                    reservation = bpf_map_lookup_elem(&upd_port_reservation, &mapping->reservation);
                    if (!reservation) {
                        return XDP_DROP;
                    }

                    iph->daddr = reservation->remote_addr;
                    iph->saddr = rule->bind_addr;
                    iph->ttl = 64;
                    udph->source = htons(rule->bind_port);
                    udph->dest = htons(reservation->remote_port);

                    update_iph_checksum(iph);

                    swap_dest_src_hwaddr(data);

                    return XDP_TX;
                } else {
                    return XDP_DROP;
                }
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