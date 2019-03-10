#pragma once

void load_skb_program(const char *ifname, int ifindex, int xsk_map_fd);

extern int a2s_cache_map_fd;

struct a2s_info_cache_entry {
    uint64_t age;
    uint64_t misses;
    uint8_t *udp_data;
    uint16_t len;
};
