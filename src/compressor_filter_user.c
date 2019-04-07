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

#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/if_link.h>
#include <libbpf.h>
#include <bpf.h>
#include <signal.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <sys/sysinfo.h>

#include "compressor_filter_user.h"
#include "compressor_cache_user.h"
#include "config.h"
#include "bpf_load.h"

static void cleanup_interface(void) {
    bpf_set_link_xdp_fd(ifindex, -1, XDP_FLAGS_SKB_MODE);
}

static void int_exit(int sig) {
    cleanup_interface();
    exit(0);
}

static void init_rate_limit_maps(int rate_limit_map_fd) {
    int num_cpus = get_nprocs_conf();
    if (num_cpus > MAX_CPUS) {
        num_cpus = MAX_CPUS;
    }

    for (uint32_t cpu_id = 0; cpu_id < num_cpus; cpu_id++) {
        uint32_t cpu_ratelimit_lru = bpf_create_map(BPF_MAP_TYPE_LRU_HASH, sizeof(uint32_t), sizeof(struct ip_addr_history), LRU_SIZE, 0);
        if (cpu_ratelimit_lru == -1) {
            fprintf(stderr, "Error creating LRU hash for ratelimiting\n");
            perror("bpf_create_mape()");
            exit(1);
        }

        if (bpf_map_update_elem(rate_limit_map_fd, &cpu_id, &cpu_ratelimit_lru, BPF_ANY)) {
            fprintf(stderr, "Error storing per-CPU LRU\n");
            perror("bpf_map_update_elem()");
            exit(1);
        }
    }
}

struct compressor_maps *load_xdp_prog(struct forwarding_rule **forwarding, struct config *cfg) {
    char *filename = "/etc/compressor/compressor_filter_kern.o";

    if (load_bpf_file(filename)) {
        fprintf(stderr, "Error loading BPF file\n");
        fprintf(stderr, "%s\n", bpf_log_buf);
        return 0;
    }

    if (!map_fd[0]) {
        fprintf(stderr, "Error finding config map in XDP program\n");
        return 0;
    }
    int config_map_fd = map_fd[0];

    if (!map_fd[1]) {
        fprintf(stderr, "Error finding forwarding map in XDP program\n");
        return 0;
    }
    int forwarding_rules_fd = map_fd[1];

    if (!map_fd[2]) {
        fprintf(stderr, "Error finding tunneling map in XDP program\n");
        return 0;
    }
    int tunnel_map_fd = map_fd[2];

    if (!map_fd[3]) {
        fprintf(stderr, "Error finding XSK map in XDP program\n");
        return 0;
    }
    int xsk_map_fd = map_fd[3];

    if(!map_fd[4]) {
        fprintf(stderr, "Error finding A2S_INFO cache map in XDP program\n");
        return 0;
    }
    int a2s_cache_map_fd = map_fd[4];

    if(!map_fd[6]) {
        fprintf(stderr, "Error finding rate limit map in XDP program\n");
        return 0;
    }
    int rate_limit_map_fd = map_fd[6];

    if(!map_fd[7]) {
        fprintf(stderr, "Error finding new connection map in XDP program\n");
        return 0;
    }
    int new_conn_map_fd = map_fd[7];


    init_rate_limit_maps(rate_limit_map_fd);

    int idx = 0;
    int err = 0;
    struct forwarding_rule *rule;
    while ((rule = forwarding[idx]) != NULL) {
        struct in_addr bind_addr;
        bind_addr.s_addr = rule->bind_addr;
        struct in_addr dest_addr;
        dest_addr.s_addr = rule->to_addr;
        struct in_addr inner_addr;
        inner_addr.s_addr = rule->inner_addr;

        char bind_str[32];
        char dest_str[32];
        char inner_str[32];
        strcpy(bind_str, inet_ntoa(bind_addr));
        strcpy(dest_str, inet_ntoa(dest_addr));
        strcpy(inner_str, inet_ntoa(inner_addr));

        printf(
            "Adding forwarding rule %s:%d <--> %s[%s]:%d (%d, A2S_INFO cache: %s)\n",
            bind_str,
            rule->bind_port,
            dest_str,
            inner_str,
            rule->to_port,
            rule->steam_port,
            rule->a2s_info_cache ? "on" : "off"
        );
        err = bpf_map_update_elem(forwarding_rules_fd, &rule->bind_addr, rule, BPF_NOEXIST);
        if (err) {
            fprintf(stderr, "Store forwarding IP map failed: (err:%d)\n", err);
            perror("bpf_map_update_elem");
            return 0;
        }

        uint64_t key = ((uint64_t)rule->to_addr << 32) | rule->inner_addr;
        err = bpf_map_update_elem(tunnel_map_fd, &key, rule, BPF_NOEXIST);
        if (err) {
            fprintf(stderr, "Store tunnel IP map failed: (err:%d)\n", err);
            perror("bpf_map_update_elem");
            return 0;
        }

        if (rule->a2s_info_cache) {
            struct a2s_info_cache_entry cache_entry = {
                .age = 0,
                .misses = 0,
                .udp_data = NULL,
                .len = 0
            };

            // A2S_INFO caching operates on the bind address
            err = bpf_map_update_elem(a2s_cache_map_fd, &rule->bind_addr, &cache_entry, BPF_NOEXIST);
            if (err) {
                fprintf(stderr, "Error prepopulating A2S_INFO cache: (err:%d)\n", err);
                perror("bpf_map_update_elem");
                return 0;
            }
        }

        idx++;
    }

    uint32_t key = 0;
    err = bpf_map_update_elem(config_map_fd, &key, cfg, BPF_ANY);
    if (err) {
        fprintf(stderr, "Store config failed: (err:%d)\n", err);
        perror("bpf_map_update_elem");
        return 0;
    }

    signal(SIGINT, int_exit);
    signal(SIGTERM, int_exit);
    signal(SIGKILL, int_exit);
    atexit(cleanup_interface);

    if (bpf_set_link_xdp_fd(ifindex, prog_fd[0], XDP_FLAGS_SKB_MODE) < 0) {
        fprintf(stderr, "link set xdp failed\n");
        return 0;
    }

    struct compressor_maps *maps = malloc(sizeof(struct compressor_maps));
    maps->a2s_cache_map_fd = a2s_cache_map_fd;
    maps->xsk_map_fd = xsk_map_fd;
    maps->rate_limit_map_fd = rate_limit_map_fd;
    maps->new_conn_map_fd = new_conn_map_fd;

    return maps;
}
