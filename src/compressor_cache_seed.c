#include <arpa/inet.h>
#include <pthread.h>
#include <memory.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <bpf.h>
#include <unistd.h>

#include "compressor_cache_seed.h"
#include "compressor_cache_user.h"
#include "xassert.h"

struct seed_arg {
    struct forwarding_rule *rule;
    int cache_map_fd;
};

void *seed_cache(void *arg) {
    struct seed_arg *params = (struct seed_arg *)arg;
    int sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    xassert(sock_fd != -1);

    struct timeval tv;
    tv.tv_sec = 4;
    tv.tv_usec = 0;

    xassert(setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval)) >= 0);
    xassert(setsockopt(sock_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(struct timeval)) >= 0);

    struct sockaddr_in servaddr = { 0 };
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = params->rule->bind_addr;
    servaddr.sin_port = htons(params->rule->bind_port);
    socklen_t len = sizeof(struct sockaddr_in);
    for (;;) {
        int sent = sendto(sock_fd, "\xff\xff\xff\xffTSource Engine Query\x00", 25, MSG_CONFIRM, (struct sockaddr *)&servaddr, sizeof(servaddr));
        if (sent == -1) {
            perror("sendto()");
            continue;
        }

        char buffer[255];
        int n = recvfrom(sock_fd, buffer, sizeof(buffer), MSG_WAITALL, (struct sockaddr *)&servaddr, &len);
        if (n == -1) {
            perror("recvfom()");
            continue;
        }

        struct a2s_info_cache_entry entry;
        struct timespec tspec;
        clock_gettime(CLOCK_MONOTONIC, &tspec);

        bpf_map_lookup_elem(params->cache_map_fd, &params->rule->bind_addr, &entry);
        if (entry.udp_data) {
            free(entry.udp_data);
        }

        entry.udp_data = malloc(n);
        memcpy(entry.udp_data, buffer, n);
        entry.len = n;
        entry.age = (tspec.tv_sec * 1e9) + tspec.tv_nsec;
        entry.misses = 0;
        bpf_map_update_elem(params->cache_map_fd, &params->rule->bind_addr, &entry, BPF_ANY);

        sleep((params->rule->cache_time > 30) ? params->rule->cache_time - 1 : 30);
    }
}

void start_seed_thread(struct forwarding_rule *rule, int cache_map_fd) {
    struct forwarding_rule *rule_copy = malloc(sizeof(struct forwarding_rule));
    memcpy(rule_copy, rule, sizeof(struct forwarding_rule));
    struct seed_arg* params = malloc(sizeof(struct seed_arg));
    params->rule = rule_copy;
    params->cache_map_fd = cache_map_fd;

    pthread_t new_thread;
    xassert(pthread_create(&new_thread, NULL, seed_cache, (void *)params) == 0);
}

void start_cache_seeding(int cache_map_fd, struct forwarding_rule **rules) {
    struct forwarding_rule *rule;
    int idx = 0;
    while ((rule = rules[idx++]) != NULL) {
        if (rule->a2s_info_cache) {
            start_seed_thread(rule, cache_map_fd);
        }
    }
}
