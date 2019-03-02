#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <sys/resource.h>
#include <libconfig.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libbpf.h>
#include <bpf.h>
#include <signal.h>

static int ifindex;

static void cleanup_interface(void) {
    bpf_set_link_xdp_fd(ifindex, -1, XDP_FLAGS_SKB_MODE);
}

static void int_exit(int sig) {
    cleanup_interface();
    exit(0);
}

int load_xdp_prog(const char *dir) {
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
        fprintf(stderr, "Error finding map in XDP program\n");
        return 1;
    }
    
    int map_fd = bpf_map__fd(map);
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

        if ((res = load_xdp_prog(argv[0])) != 0) {
            return res;
        }
    } else {
        perror("Error reading configuration file");
        return 1;
    }

    while (1) {
        sleep(2);
    }
    
    return 0;
}