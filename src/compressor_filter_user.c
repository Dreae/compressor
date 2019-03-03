#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/if_link.h>
#include <libbpf.h>
#include <bpf.h>
#include <signal.h>
#include <stdlib.h>
#include "compressor_filter_user.h"

static void cleanup_interface(void) {
    bpf_set_link_xdp_fd(ifindex, -1, XDP_FLAGS_SKB_MODE);
}

static void int_exit(int sig) {
    cleanup_interface();
    exit(0);
}

int load_xdp_prog(void) {
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
