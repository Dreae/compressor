#include <linux/if_packet.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <libbpf.h>
#include "bpf_load.h"


int open_raw_socket(const char *ifname, int ifindex) {
    struct sockaddr_ll sll;
    int sock = socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
    if (sock < 0) {
        fprintf(stderr, "Unable to open raw socket\n");
        perror("socket()");

        return -1;
    }

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        fprintf(stderr, "Unable to bind raw socket\n");
        perror("bind()");

        return -1;
    }

    return sock;
}

int load_skb_program(const char *ifname, int ifindex) {
    char *filename = "/etc/compressor/compressor_cache_kern.o";

    if (load_bpf_file(filename)) {
        fprintf(stderr, "Error loading BPF file\n");
        fprintf(stderr, "%s\n", bpf_log_buf);
        return -1;
    }

    if (!prog_fd[1]) {
        fprintf(stderr, "Error loading socket filter\n");
        return -1;
    }

    int sock = open_raw_socket(ifname, ifindex);
    if (sock == -1) {
        return -1;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd[1], sizeof(prog_fd[1])) != 0) {
        fprintf(stderr, "Error attaching socket filter\n");
        perror("setsockopt()");

        return -1;
    }

    return 0;
}