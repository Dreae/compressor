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

#include "compressor_filter_user.h"
#include "config.h"
#include "bpf_load.h"

static void cleanup_interface(void) {
    bpf_set_link_xdp_fd(ifindex, -1, XDP_FLAGS_SKB_MODE);
}

static void int_exit(int sig) {
    cleanup_interface();
    exit(0);
}

int load_xdp_prog(struct service_def **services, struct forwarding_rule **forwarding, struct config *cfg) {
    char *filename = "/etc/compressor/compressor_filter_kern.o";

    if (load_bpf_file(filename)) {
        fprintf(stderr, "%s", bpf_log_buf);
        return 1;
    }

    if (!map_fd[0]) {
        fprintf(stderr, "Error finding TCP service map in XDP program\n");
        return 1;
    }
    int tcp_service_fd = map_fd[0];

    if (!map_fd[1]) {
        fprintf(stderr, "Error finding UDP service map in XDP program\n");
        return 1;
    }
    int udp_service_fd = map_fd[1];

    if (!map_fd[2]) {
        fprintf(stderr, "Error finding config map in XDP program\n");
        return 1;
    }
    int config_map_fd = map_fd[2];

    if (!map_fd[3]) {
        fprintf(stderr, "Error finding forwarding map in XDP program\n");
        return 1;
    }
    int forwarding_rules_fd = map_fd[3];

    if (!map_fd[4]) {
        fprintf(stderr, "Error finding tunneling map in XDP program\n");
        return 1;
    }
    int tunnel_map_fd = map_fd[4];

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

        printf("Adding forwarding rule %s:%d <--> %s:%d (%d)\n", bind_str, rule->bind_port, dest_str, rule->to_port, rule->steam_port);
        uint32_t port = (uint32_t)rule->bind_port;
        uint32_t steam_port = (uint32_t)rule->steam_port;

        err = bpf_map_update_elem(forwarding_rules_fd, &rule->bind_addr, rule, BPF_ANY);
        if (err) {
            fprintf(stderr, "Store forwarding IP map failed: (err:%d)\n", err);
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

    signal(SIGINT, int_exit);
    signal(SIGTERM, int_exit);
    signal(SIGKILL, int_exit);
    atexit(cleanup_interface);

    if (bpf_set_link_xdp_fd(ifindex, prog_fd[0], XDP_FLAGS_SKB_MODE) < 0) {
        fprintf(stderr, "link set xdp failed\n");
        return 1;
    }

    return 0;
}
