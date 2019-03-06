#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/if_link.h>
#include <libbpf.h>
#include <bpf.h>
#include <signal.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include "compressor_filter_user.h"
#include "config.h"

static void cleanup_interface(void) {
    bpf_set_link_xdp_fd(ifindex, -1, XDP_FLAGS_SKB_MODE);
}

static void int_exit(int sig) {
    cleanup_interface();
    exit(0);
}

int load_xdp_prog(struct service_def **services, struct forwarding_rule **forwarding, struct config *cfg) {
    const char *filename = "/etc/compressor/compressor_filter_kern.o";

    struct bpf_prog_load_attr prog_load_attr = {
        .prog_type = BPF_PROG_TYPE_XDP,
    };
    prog_load_attr.file = filename;

    struct bpf_object *obj;
    int prog_fd;
    if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd)) {
        fprintf(stderr, "Error loading XDP program");
        return 1;
    }

    struct bpf_map *map;
    map = bpf_map__next(NULL, obj);
    if (!map) {
        fprintf(stderr, "Error finding IP blacklist in XDP program\n");
        return 1;
    }
    int ip_blacklist_fd = bpf_map__fd(map);
    
    map = bpf_map__next(map, obj);
    if (!map) {
        fprintf(stderr, "Error finding TCP service map in XDP program\n");
        return 1;
    }
    int tcp_service_fd = bpf_map__fd(map);

    map = bpf_map__next(map, obj);
    if (!map) {
        fprintf(stderr, "Error finding UDP service map in XDP program\n");
        return 1;
    }
    int udp_service_fd = bpf_map__fd(map);

    map = bpf_map__next(map, obj);
    if (!map) {
        fprintf(stderr, "Error finding config map in XDP program\n");
        return 1;
    }
    int config_map_fd = bpf_map__fd(map);

    map = bpf_map__next(map, obj);
    if (!map) {
        fprintf(stderr, "Error finding forwarding map in XDP program\n");
        return 1;
    }
    int forwarding_rules_fd = bpf_map__fd(map);

    map = bpf_map__next(map, obj);
    if (!map) {
        fprintf(stderr, "Error finding tunneling map in XDP program\n");
        return 1;
    }
    int tunnel_map_fd = bpf_map__fd(map);

    struct service_def *service;
    int idx = 0;
    uint8_t enable = 1;

    int err = 0;
    while ((service = services[idx]) != NULL) {
        uint32_t dest = (uint32_t)service->port;
        if (service->proto == PROTO_TCP) {
            err = bpf_map_update_elem(tcp_service_fd, &dest, &enable, BPF_ANY);
            printf("Adding service %d/tcp\n", dest);
        } else if (service->proto == PROTO_UDP) {
            err = bpf_map_update_elem(udp_service_fd, &dest, &enable, BPF_ANY);
            printf("Adding service %d/udp\n", dest);
        } else {
            fprintf(stderr, "Got unknown service protocol %d\n", service->proto);
        }

        if (err) {
            fprintf(stderr, "Store service port failed: (err:%d)\n", err);
            perror("bpf_map_update_elem");
            return 1;
        }

        idx++;
    }

    struct forwarding_rule *rule;
    idx = 0;
    while ((rule = forwarding[idx]) != NULL) {
        struct in_addr bind_addr;
        bind_addr.s_addr = rule->bind_addr;
        struct in_addr dest_addr;
        dest_addr.s_addr = rule->to_addr;

        char bind_str[32];
        char dest_str[32];
        strcpy(bind_str, inet_ntoa(bind_addr));
        strcpy(dest_str, inet_ntoa(dest_addr));

        printf("Adding forwarding rule %s:%d <--> %s:%d\n", bind_str, rule->bind_port, dest_str, rule->to_port);
        uint64_t key = rule->bind_addr;
        err = bpf_map_update_elem(forwarding_rules_fd, &key, rule, BPF_ANY);
        if (err) {
            fprintf(stderr, "Store forwarding rule failed: (err:%d)\n", err);
            perror("bpf_map_update_elem");
            return 1;
        }
        err = bpf_map_update_elem(tunnel_map_fd, &rule->to_addr, rule, BPF_ANY);
        if (err) {
            fprintf(stderr, "Store forwarding rule failed: (err:%d)\n", err);
            perror("bpf_map_update_elem");
            return 1;
        }

        idx++;
    }

    uint32_t key = 0;
    err = bpf_map_update_elem(config_map_fd, &key, cfg, BPF_ANY);
    if (err) {
        fprintf(stderr, "Store config failed: (err:%d)\n", err);
        perror("bpf_map_update_elem");
        return 1;
    }
    
    if (!prog_fd) {
        perror("load_bpf_file");
        return 1;
    }


    signal(SIGINT, int_exit);
    signal(SIGTERM, int_exit);
    signal(SIGKILL, int_exit);
    atexit(cleanup_interface);

    if (bpf_set_link_xdp_fd(ifindex, prog_fd, XDP_FLAGS_SKB_MODE) < 0) {
        fprintf(stderr, "link set xdp failed\n");
        return 1;
    }

    return 0;
}
