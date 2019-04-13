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

#include <arpa/inet.h>
#include <pthread.h>
#include <memory.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <bpf.h>
#include <unistd.h>
#include <stdlib.h>
#include <hiredis/hiredis.h>
#include <hiredis/async.h>
#include <hiredis/adapters/libevent.h>

#include "compressor_cache_seed.h"
#include "compressor_cache_user.h"
#include "xassert.h"
#include "checksum.h"

struct seed_arg {
    struct forwarding_rule **rules;
    int cache_map_fd;
    uint32_t redis_addr;
    uint16_t redis_port;
};

struct subscribe_arg {
    struct forwarding_rule *rule;
    int cache_map_fd;
};

struct publish_arg {
    struct forwarding_rule **rules;
    redisContext *redis;
    int cache_map_fd;
};

static pthread_mutex_t cache_notif_lock;
static pthread_cond_t cache_notif_server;
static uint32_t cache_server;
static bool enabled = false;

void on_server_update(redisAsyncContext *redis, void *reply, void *data) {
    if (reply == NULL) {
        return;
    }
    redisReply *r = reply;
    struct subscribe_arg *arg = data;
    if (r->type == REDIS_REPLY_ARRAY) {
        if (r->elements != 3 || strncmp(r->element[0]->str, "message", r->element[0]->len) != 0 || r->element[2]->len < 4) {
            return;
        }

        struct a2s_info_cache_entry entry = { 0 };

        struct timespec tspec;
        clock_gettime(CLOCK_MONOTONIC, &tspec);
        uint64_t kernel_time = (tspec.tv_sec * 1e9) + tspec.tv_nsec;

        get_cache_wlock();
        bpf_map_lookup_elem(arg->cache_map_fd, &arg->rule->bind_addr, &entry);
        if (entry.hits) {
            entry.hits = 0;
            entry.misses = 0;
        }

        uint8_t *old_data = entry.udp_data;

        void *redis_data = (void *)r->element[2]->str;
        uint16_t ttl = *((uint16_t *)redis_data);
        void *data = redis_data + sizeof(uint16_t);
        uint64_t data_len = r->element[2]->len - sizeof(uint16_t);
        entry.udp_data = malloc(data_len);
        memcpy(entry.udp_data, data, data_len);

        entry.len = data_len;
        entry.age = kernel_time - (arg->rule->cache_time - (ttl * 1e9));
        entry.csum = csum_partial(entry.udp_data, entry.len, 0);

        bpf_map_update_elem(arg->cache_map_fd, &arg->rule->bind_addr, &entry, BPF_ANY);
        release_cache_lock();

        if (old_data) {
            free(old_data);
        }
    }
}

void notify_a2s_redis(uint32_t server) {
    if (enabled) {
        pthread_mutex_lock(&cache_notif_lock);
        cache_server = server;
        pthread_cond_signal(&cache_notif_server);
        pthread_mutex_unlock(&cache_notif_lock);
    }
}

void *signal_cache(void *arg) {
    struct publish_arg *params = (struct publish_arg *)arg;

    for(;;) {
        pthread_mutex_lock(&cache_notif_lock);
        pthread_cond_wait(&cache_notif_server, &cache_notif_lock);

        struct forwarding_rule *rule;
        int idx = 0;
        while((rule = params->rules[idx++]) != NULL) {
            if (rule->bind_addr == cache_server) {
                break;
            }
        }

        if (rule != NULL) {
            struct a2s_info_cache_entry entry = { 0 };
            get_cache_rlock();
            bpf_map_lookup_elem(params->cache_map_fd, &cache_server, &entry);
            if (entry.udp_data) {
                struct timespec tspec;
                clock_gettime(CLOCK_MONOTONIC, &tspec);
                uint64_t kernel_time = (tspec.tv_sec * 1e9) + tspec.tv_nsec;

                if (kernel_time - entry.age < rule->cache_time) {
                    uint16_t ttl = (rule->cache_time - (kernel_time - entry.age)) / 1e9;
                    uint8_t *buffer = calloc(entry.len + sizeof(uint16_t) + 1, sizeof(uint8_t));
                    *buffer = ttl;
                    memcpy(buffer + sizeof(uint16_t), entry.udp_data, entry.len);

                    struct in_addr addr = {
                        .s_addr = cache_server
                    };

                    redisCommand(params->redis, "PUBLISH %s %b", inet_ntoa(addr), buffer, entry.len + sizeof(uint16_t));
                }
            }
            release_cache_lock();
        }

        pthread_mutex_unlock(&cache_notif_lock);
    }
}

void *seed_cache(void *arg) {
    struct seed_arg *params = (struct seed_arg *)arg;

    struct event_base *base = event_base_new();

    struct in_addr addr;
    addr.s_addr = params->redis_addr;
    redisAsyncContext *sub_redis = redisAsyncConnect(inet_ntoa(addr), params->redis_port);
    if (sub_redis->err) {
        fprintf(stderr, "Error connected to redis: %s\n", sub_redis->errstr);
        exit(1);
    }

    redisContext *com_redis = redisConnect(inet_ntoa(addr), params->redis_port);
    if (com_redis->err) {
        fprintf(stderr, "Error connected to redis: %s\n", com_redis->errstr);
        exit(1);
    }
    redisEnableKeepAlive(com_redis);

    redisLibeventAttach(sub_redis, base);
    struct forwarding_rule *rule;
    int idx = 0;
    while ((rule = params->rules[idx++]) != NULL) {
        struct subscribe_arg *arg = malloc(sizeof(struct subscribe_arg));
        arg->cache_map_fd = params->cache_map_fd;
        arg->rule = rule;

        struct in_addr addr = {
            .s_addr = rule->bind_addr
        };

        redisAsyncCommand(sub_redis, on_server_update, arg, "SUBSCRIBE %s", inet_ntoa(addr));
    }

    struct publish_arg *publish_params = malloc(sizeof(struct publish_arg));
    publish_params->cache_map_fd = params->cache_map_fd;
    publish_params->rules = params->rules;
    publish_params->redis = com_redis;

    pthread_t publish_thread;
    xassert(pthread_create(&publish_thread, NULL, signal_cache, (void *)publish_params) == 0);

    event_base_dispatch(base);

    fprintf(stderr, "Redis event loop exited, cleaning up\n");
    event_base_free(base);

    return NULL;
}

void start_seed_thread(struct forwarding_rule **rules, int cache_map_fd, uint32_t redis_addr, uint16_t redis_port) {
    struct seed_arg* params = malloc(sizeof(struct seed_arg));
    params->rules = rules;
    params->cache_map_fd = cache_map_fd;
    params->redis_addr = redis_addr;
    params->redis_port = redis_port;

    pthread_t cache_thread;
    xassert(pthread_create(&cache_thread, NULL, seed_cache, (void *)params) == 0);
}

void start_cache_seeding(int cache_map_fd, struct forwarding_rule **rules, uint32_t redis_addr, uint16_t redis_port) {
    struct forwarding_rule *current_rule;
    int idx = 0;

    struct forwarding_rule **rules_copy = calloc(255, sizeof(void *));

    while ((current_rule = rules[idx]) != NULL) {
        rules_copy[idx] = malloc(sizeof(struct forwarding_rule));
        memcpy(rules_copy[idx], current_rule, sizeof(struct forwarding_rule));
        idx++;
    }

    printf("Starting redis seed threads\n");
    xassert(pthread_mutex_init(&cache_notif_lock, NULL) == 0);
    xassert(pthread_cond_init(&cache_notif_server, NULL) == 0);

    start_seed_thread(rules_copy, cache_map_fd, redis_addr, redis_port);

    enabled = true;
}
