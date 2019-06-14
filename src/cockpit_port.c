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

#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <bpf.h>

#include "cockpit_port.h"
#include "xassert.h"

int read_exact(uint8_t *buf, int len) {
    int i, got = 0;

    do {
        if ((i = read(0, buf + got, len - got)) <= 0)
            return (i);
        got += i;
    } while (got < len);

    return (len);
}

int write_exact(uint8_t *buf, int len) {
    int i, wrote = 0;

    do {
        if ((i = write(1, buf + wrote, len - wrote)) <= 0)
            return (i);
        wrote += i;
    } while (wrote < len);

    return (len);
}

int read_cmd(uint8_t *buf) {
    int len;

    if (read_exact(buf, 2) != 2) {
        return (-1);
    }
    len = (buf[0] << 8) | buf[1];
    return read_exact(buf, len);
}

int write_cmd(uint8_t *buf, int len) {
    uint8_t li;

    li = (len >> 8) & 0xff;
    write_exact(&li, 1);

    li = len & 0xff;
    write_exact(&li, 1);

    return write_exact(buf, len);
}

void update_server(uint8_t *buffer, int forwarding_map_fd) {
  struct server_update_msg *update = (struct server_update_msg *)buffer;

  struct forwarding_rule rule;
  bpf_map_lookup_elem(forwarding_map_fd, &update->bind_addr, &rule);
  rule.bind_addr = update->bind_addr;
  rule.bind_port = update->bind_port;
  rule.to_addr = update->dest_addr;
  rule.to_port = update->dest_port;
  rule.inner_addr = update->internal_addr;
  rule.a2s_info_cache = update->a2s_info_cache;
  rule.cache_time = update->cache_time * 1e9;

  bpf_map_update_elem(forwarding_map_fd, &rule.bind_addr, &rule, BPF_ANY);
}

void *read_cockpit_input(void *arg) {
  struct compressor_maps *maps = (struct compressor_maps *)arg;

  uint8_t buffer[1024];
  while (read_cmd(buffer) > 0) {
    if (buffer[0] == 1) {
      update_server(&buffer[1], maps->forwarding_map_fd);
    }
  }

  // stdin closed, we should exit
  exit(1);
}

void *update_cockpit_pps(void *arg) {
  return NULL;
}

void start_cockpit_port(struct compressor_maps *maps) {
  pthread_t cockpit_thread, poll_thread;
  xassert(pthread_create(&cockpit_thread, NULL, read_cockpit_input, (void *)maps) == 0);
  xassert(pthread_create(&poll_thread, NULL, update_cockpit_pps, (void *)maps) == 0);
}