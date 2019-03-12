#include <pthread.h>
#include <bpf.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "compressor_ratelimit_user.h"
#include "xassert.h"

void *reclaim_old_ips(void *fd) {
    int map_fd = *((int *)fd);
    for (;;) {
        sleep(120);

        uint32_t last_ip = 0;
        uint32_t curr_ip = 0;
        while (bpf_map_get_next_key(map_fd, &last_ip, &curr_ip) == 0) {
            struct ip_addr_history entry;
            bpf_map_lookup_elem(map_fd, &curr_ip, &entry);

            struct timespec t;
            clock_gettime(CLOCK_MONOTONIC, &t);
            uint64_t now = (t.tv_sec * 1e9) + t.tv_nsec;
            if (now - entry.last_seen > 1.2e11) {
                bpf_map_delete_elem(map_fd, &curr_ip);
            } else {
                entry.hits = 0;
                bpf_map_update_elem(map_fd, &curr_ip, &entry, BPF_EXIST);
            }

            last_ip = curr_ip;
        }
    }
}

void *reset_ratelimit(void *fd) {
    int map_fd = *((int *)fd);
    uint32_t key = 0;
    uint_fast64_t new_val = 0;
    for (;;) {
        sleep(1);
        
        bpf_map_update_elem(map_fd, &key, &new_val, BPF_EXIST);
    }
}

void start_rlimit_mon(int rate_limit_map_fd, int new_ip_map_fd) {
    pthread_t reclaim_thread;
    int *rate_limit_map_ptr = calloc(1, sizeof(int));
    *rate_limit_map_ptr = rate_limit_map_fd;
    xassert(pthread_create(&reclaim_thread, NULL, reclaim_old_ips, (void *)rate_limit_map_ptr) == 0);
    pthread_detach(reclaim_thread);

    pthread_t timer_thread;
    int *new_ip_map_ptr = calloc(1, sizeof(int));
    *new_ip_map_ptr = new_ip_map_fd;
    xassert(pthread_create(&timer_thread, NULL, reset_ratelimit, (void *)new_ip_map_ptr) == 0);
}