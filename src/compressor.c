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

#include <linux/if_link.h>
#include <net/if.h>
#include <sys/resource.h>
#include <libconfig.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <libbpf.h>

#include "compressor.h"
#include "config.h"
#include "cockpit_port.h"

int ifindex;
#include "compressor_filter_user.h"
#include "compressor_cache_user.h"
#include "compressor_cache_seed.h"

int main(int argc, char **argv) {
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        perror("setrlimit(RLIMIT_MEMLOCK)");
        return 1;
    }

    config_t config;
    config_init(&config);

    FILE *fd = fopen("/etc/compressor/compressor.conf", "r");
    if (fd) {
        int res = config_read(&config, fd);
        if (res == CONFIG_FALSE) {
            fprintf(stderr, "Error parsing configuration file: %s\n", config_error_text(&config));
            return 1;
        }
        
        const char *interface;
        if (config_lookup_string(&config, "interface", &interface) == CONFIG_FALSE) {
            fprintf(stderr, "Error: No interface defined in configuration file\n");
            return 1;
        }

        ifindex = if_nametoindex(interface);
        if (!ifindex) {
            perror("Error getting interface");
            return 1;
        }
        bpf_set_link_xdp_fd(ifindex, -1, XDP_FLAGS_DRV_MODE);
        bpf_set_link_xdp_fd(ifindex, -1, XDP_FLAGS_SKB_MODE);

        struct config cfg = { 0 };
        long long new_conn_limit = 0;
        if (config_lookup_int64(&config, "new_conn_limit", &new_conn_limit) == CONFIG_FALSE) {
            new_conn_limit = 30;
            fprintf(stderr, "Warning: no connection limit set; defaulting to 30\n");
        }

        long long rate_limit = 0;
        if (config_lookup_int64(&config, "ip_rate_limit", &rate_limit) == CONFIG_FALSE) {
            rate_limit = 12000;
            fprintf(stderr, "Warning: no rate limit set; defaulting to 12000\n");
        }

        int tcp_exclude = 0;

        if (config_lookup_int(&config, "tcp_exclude", &tcp_exclude) == CONFIG_FALSE)
        {
            tcp_exclude = 0;
        }

        int rxqueues = 0;

        if (config_lookup_int(&config, "rxqueues", &rxqueues) == CONFIG_FALSE)
        {
            rxqueues = 0;
        }

        cfg.rate_limit = rate_limit;
        cfg.new_conn_limit = new_conn_limit;
        cfg.tcp_exclude = tcp_exclude;
        cfg.rxqueues = rxqueues;

        int cockpit_enabled = 0;
        config_lookup_bool(&config, "cockpit_enabled", &cockpit_enabled);

        config_setting_t *forwarding = config_lookup(&config, "srcds");
        struct forwarding_rule **forwarding_rules = calloc(255, sizeof(struct forwarding_rule *));
        if (forwarding) {
            int num_rules = 0;

            config_setting_t *config_rule;
            int idx = 0;
            while ((config_rule = config_setting_get_elem(forwarding, idx)) != NULL) {
                struct forwarding_rule *fwd_rule = parse_forwarding_rule(config_rule);

                if (fwd_rule) {
                    forwarding_rules[num_rules] = fwd_rule;
                    num_rules++;
                }

                idx++;
            }
        }

        config_setting_t *redis = config_lookup(&config, "redis_cache");
        uint32_t redis_addr = 0;
        int redis_port = 0;
        if (redis) {
            const char *redis_addr_str;
            if (config_setting_lookup_string(redis, "address", &redis_addr_str) == CONFIG_FALSE) {
                fprintf(stderr, "Error reading redis config, no address defined\n");
                return 1;
            }
            struct in_addr redis_in_addr;
            if (!inet_aton(redis_addr_str, &redis_in_addr)) {
                fprintf(stderr, "Error parsing redis address: %s", redis_addr_str);
                return 1;
            }
            redis_addr = redis_in_addr.s_addr;

            if (config_setting_lookup_int(redis, "port", &redis_port) == CONFIG_FALSE) {
                fprintf(stderr, "Error reading redis config, no port defined\n");
                return 1;
            }
        }

        struct compressor_maps *maps;
        if (!(maps = load_xdp_prog(forwarding_rules, &cfg))) {
            return 1;
        }

        load_skb_program(interface, ifindex, maps->xsk_map_fd, maps->a2s_cache_map_fd, &cfg);
        if (redis_addr && redis_port) {
            start_cache_seeding(maps->a2s_cache_map_fd, forwarding_rules, redis_addr, redis_port);
        }
        if(cockpit_enabled) {
            start_cockpit_port(maps);
        }

        free_array((void **)forwarding_rules);
        config_destroy(&config);
    } else {
        perror("Error reading configuration file");
        return 1;
    }

    while (1) {
        sleep(2);
    }
    
    return 0;
}
