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

#include <assert.h>
#include <linux/if_packet.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <libbpf.h>
#include <linux/if_xdp.h>
#include <linux/socket.h>
#include <linux/if_link.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/udp.h>
#include <sys/mman.h>
#include <asm-generic/mman.h>
#include <unistd.h>
#include <sys/resource.h>
#include <stdlib.h>
#include <pthread.h>
#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <poll.h>
#include <time.h>
#include <sys/sysinfo.h>

#include "bpf_load.h"
#include "srcds_util.h"
#include "compressor_cache_user.h"
#include "compressor_cache_seed.h"
#include "compressor_filter_user.h"
#include "xassert.h"
#include "checksum.h"

#ifndef AF_XDP
#define AF_XDP 44
#endif
#ifndef SOL_XDP
#define SOL_XDP 283
#endif

#define NUM_FRAMES 131072
#define FRAME_HEADROOM 0
#define FRAME_SHIFT 11
#define FRAME_SIZE 2048
#define NUM_DESCS 1024
#define BATCH_SIZE 16

#define FQ_NUM_DESCS 1024
#define CQ_NUM_DESCS 1024
#define barrier() __asm__ __volatile__("" : : : "memory")
#define likely(x) __builtin_expect(!!(x), 1)

struct xdp_umem_uqueue {
    uint32_t cached_prod;
    uint32_t cached_cons;
    uint32_t mask;
    uint32_t size;
    uint32_t *producer;
    uint32_t *consumer;
    uint64_t *ring;
    void *map;
};

struct xdp_umem {
    char *frames;
    struct xdp_umem_uqueue fq;
    struct xdp_umem_uqueue cq;
    int fd;
};

struct xdp_uqueue {
    uint32_t cached_prod;
    uint32_t cached_cons;
    uint32_t mask;
    uint32_t size;
    uint32_t *producer;
    uint32_t *consumer;
    struct xdp_desc *ring;
    void *map;
};

struct xdp_sock {
    struct xdp_uqueue rx;
    struct xdp_uqueue tx;
    int sfd;
    struct xdp_umem *umem;
    uint32_t outstanding_tx;
};

static int a2s_cache_map_fd;

static pthread_mutex_t a2s_cache_lock;

__always_inline void get_cache_lock(void) {
    pthread_mutex_lock(&a2s_cache_lock);
}

__always_inline void release_cache_lock(void) {
    pthread_mutex_unlock(&a2s_cache_lock);
}

static inline int umem_nb_free(struct xdp_umem_uqueue *q, uint32_t nb) {
    uint32_t free_entries = q->cached_cons - q->cached_prod;

    if (free_entries >= nb) {
        return free_entries;
    }

    q->cached_cons = *q->consumer + q->size;

    return q->cached_cons - q->cached_prod;
}

static inline uint32_t umem_nb_avail(struct xdp_umem_uqueue *q, uint32_t nb) {
    uint32_t entries = q->cached_prod - q->cached_cons;

    if (entries == 0) {
        q->cached_prod = *q->producer;
        entries = q->cached_prod - q->cached_cons;
    }

    return (entries > nb) ? nb : entries;
}

static inline int umem_fill_to_kernel_ex(struct xdp_umem_uqueue *fq, struct xdp_desc *d, size_t nb) {
    if (umem_nb_free(fq, nb) < nb) {
        return -ENOSPC;
    }

    for (uint32_t i = 0; i < nb; i++) {
        uint32_t idx = fq->cached_prod++ & fq->mask;

        fq->ring[idx] = d[i].addr;
    }

    barrier();
    *fq->producer = fq->cached_prod;

    return 0;
}

static inline int umem_fill_to_kernel(struct xdp_umem_uqueue *fq, __u64 *d, size_t nb) {
    if (umem_nb_free(fq, nb) < nb) {
        return -ENOSPC;
    }

    for (uint32_t i = 0; i < nb; i++) {
        uint32_t idx = fq->cached_prod++ & fq->mask;

        fq->ring[idx] = d[i];
    }

    barrier();
    *fq->producer = fq->cached_prod;

    return 0;
}

static inline uint32_t umem_complete_from_kernel(struct xdp_umem_uqueue *cq, __u64 *d, size_t nb) {
    uint32_t entries = umem_nb_avail(cq, nb);

    barrier();

    for (uint32_t i = 0; i < entries; i++) {
        uint32_t idx = cq->cached_cons++ & cq->mask;
        d[i] = cq->ring[idx];
    }

    if (entries > 0) {
        barrier();
        *cq->consumer = cq->cached_cons;
    }

    return entries;
}

// xq_nb_[avail|free] and umem_nb_[avail|free] are all in support
// of batching. `cached_prod` and `cached_cons` are the consumer
// and producer pointers, cached at the start of a batch, so the
// queue can be processed in full in batches.
static inline uint32_t xq_nb_avail(struct xdp_uqueue *q, uint32_t ndescs) {
    uint32_t entries = q->cached_prod - q->cached_cons;

    if (entries == 0) {
        q->cached_prod = *q->producer;
        entries = q->cached_prod - q->cached_cons;
    }

    return (entries > ndescs) ? ndescs : entries;
}

static inline uint32_t xq_nb_free(struct xdp_uqueue *q, uint32_t ndescs) {
    uint32_t free_entries = q->cached_cons - q->cached_prod;

    if (free_entries > ndescs) {
        return free_entries;
    }

    q->cached_cons = *q->consumer + q->size;
    return q->cached_cons - q->cached_prod;
}

static inline int xq_enq(struct xdp_uqueue *uq, const struct xdp_desc *descs, int ndescs) {
    struct xdp_desc *r = uq->ring;

    if (xq_nb_free(uq, ndescs) < ndescs) {
        return -ENOSPC;
    }

    for (int i = 0; i < ndescs; i++) {
        uint32_t idx = uq->cached_prod++ & uq->mask;

        r[idx].addr = descs[i].addr;
        r[idx].len = descs[i].len;
    }

    barrier();

    *uq->producer = uq->cached_prod;
    return 0;
}

static inline int xq_deq(struct xdp_uqueue *uq, struct xdp_desc *descs, int ndescs) {
    struct xdp_desc *r = uq->ring;

    uint32_t entries = xq_nb_avail(uq, ndescs);

    barrier();
    for (uint32_t i = 0; i < entries; i++) {
        uint32_t idx = uq->cached_cons++ & uq->mask;
        descs[i] = r[idx];
    }

    if (entries > 0) {
        barrier();
        *uq->consumer = uq->cached_cons;
    }

    return entries;
}

static inline void *xq_get_data(struct xdp_sock *xsk, uint64_t addr) {
    return &xsk->umem->frames[addr];
}

static inline void kick_and_complete(struct xdp_sock *xsk) {
    if (!xsk->outstanding_tx) {
        return;
    }

    int ret = sendto(xsk->sfd, NULL, 0, MSG_DONTWAIT, NULL, 0);
    if (ret >= 0 || errno == ENOBUFS || errno == EAGAIN || errno == EBUSY) {
        __u64 descs[BATCH_SIZE];
        size_t ndescs = (xsk->outstanding_tx > BATCH_SIZE) ? BATCH_SIZE : xsk->outstanding_tx;
        uint32_t rcvd = umem_complete_from_kernel(&xsk->umem->cq, descs, ndescs);
        if (rcvd > 0) {
            umem_fill_to_kernel(&xsk->umem->fq, descs, rcvd);
            xsk->outstanding_tx -= rcvd;
        }
    }
}

static inline int save_and_enq_info_response(struct xdp_sock *xsk, const struct xdp_desc *desc, struct iphdr *iph, struct udphdr *udph, uint8_t *udp_data, uint8_t *pkt, uint8_t *pkt_end) {
    struct a2s_info_cache_entry entry;
    struct timespec tspec;
    clock_gettime(CLOCK_MONOTONIC, &tspec);

    get_cache_lock();
    bpf_map_lookup_elem(a2s_cache_map_fd, &iph->saddr, &entry);
    if (entry.udp_data) {
        free(entry.udp_data);
    }

    if (entry.hits) {
        entry.misses = 0;
        entry.hits = 0;
    }

    uint16_t len = desc->len - sizeof(struct ethhdr) - sizeof(struct iphdr) - sizeof(struct udphdr);

    entry.udp_data = calloc(sizeof(uint8_t), len + 1);
    memcpy(entry.udp_data, udp_data, len);
    entry.len = len;
    entry.age = (tspec.tv_sec * 1e9) + tspec.tv_nsec;
    entry.csum = csum_partial(udp_data, len, 0);
    bpf_map_update_elem(a2s_cache_map_fd, &iph->saddr, &entry, BPF_ANY);
    release_cache_lock();

    xq_enq(&xsk->tx, desc, 1);
    xsk->outstanding_tx++;

    notify_a2s_redis(iph->saddr);

    return 1;
}

static inline int load_and_enq_info_response(struct xdp_sock *xsk, struct xdp_desc *desc, struct iphdr *iph, struct udphdr *udph, uint8_t *udp_data, uint8_t *pkt, uint8_t *pkt_end) {
    struct a2s_info_cache_entry entry;
    bpf_map_lookup_elem(a2s_cache_map_fd, &iph->saddr, &entry);

    if (likely(entry.udp_data)) {
        memcpy(udp_data, entry.udp_data, entry.len);
        int16_t len_diff = entry.len - (desc->len - sizeof(struct ethhdr) - sizeof(struct iphdr) - sizeof(struct udphdr));
        desc->len += len_diff;

        udph->len = htons(entry.len + sizeof(struct udphdr));
        iph->tot_len = htons(desc->len - sizeof(struct ethhdr));

        update_iph_checksum(iph);
        udph->check = 0;
        __wsum csum = csum_partial((void *)udph, sizeof(struct udphdr), entry.csum);
        udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, entry.len + sizeof(struct udphdr), IPPROTO_UDP, csum);

        xq_enq(&xsk->tx, desc, 1);
        xsk->outstanding_tx++;

        return 1;
    }

    return 0;
}

static void *xsk_dispatch_a2s_info(void *arg) {
    struct xdp_sock *xsk = (struct xdp_sock *)arg;
    struct pollfd fds[1];
    memset(fds, 0, sizeof(fds));

    fds[0].fd = xsk->sfd;
    fds[0].events = POLLIN;

    for (;;) {
        int ret = poll(fds, 1, 1000);
        if (ret <= 0) {
            continue;
        }

        struct xdp_desc descs[BATCH_SIZE];
        uint32_t rcvd = xq_deq(&xsk->rx, descs, BATCH_SIZE);
        if (!rcvd) {
            continue;
        }

        for (uint32_t c = 0; c < rcvd; c++) {
            void *pkt = xq_get_data(xsk, descs[c].addr);
            void *pkt_end = pkt + descs[c].len;
            struct iphdr *iph = pkt + sizeof(struct ethhdr);
            struct udphdr *udph = pkt + sizeof(struct ethhdr) + sizeof(struct iphdr);
            uint8_t *udp_data = pkt + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
            if (udph + 1 > (struct udphdr *)pkt_end || udp_data + 5 > (uint8_t *)pkt_end) {
                umem_fill_to_kernel_ex(&xsk->umem->fq, &descs[c], 1);
            }

            udph->check = 0;
            if (check_srcds_header(udp_data, 0x49)) {
                if (save_and_enq_info_response(xsk, &descs[c], iph, udph, udp_data, pkt, pkt_end)) {
                    continue;
                }
            } else if (likely(check_srcds_header(udp_data, 0x54))) {
                if (load_and_enq_info_response(xsk, &descs[c], iph, udph, udp_data, pkt, pkt_end)) {
                    continue;
                }
            }

            umem_fill_to_kernel_ex(&xsk->umem->fq, &descs[c], 1);
        }

        kick_and_complete(xsk);
    }
}

void xsk_cache_run(struct xdp_sock *xsk) {
    pthread_t pt;
    xassert(pthread_create(&pt, NULL, xsk_dispatch_a2s_info, xsk) == 0);
}

struct xdp_umem *xdp_umem_configure(int sfd) {
    int fq_size = FQ_NUM_DESCS, cq_size = CQ_NUM_DESCS;
    struct xdp_mmap_offsets off;
    socklen_t optlen = sizeof(off);
    struct xdp_umem_reg mr;

    struct xdp_umem *umem = calloc(1, sizeof(struct xdp_umem));
    void *bufs;
    xassert(posix_memalign(&bufs, getpagesize(), NUM_FRAMES * FRAME_SIZE) == 0);

    mr.addr = (uint64_t)bufs;
    mr.len = NUM_FRAMES * FRAME_SIZE;
    mr.chunk_size = FRAME_SIZE;
    mr.headroom = FRAME_HEADROOM;

    xassert(setsockopt(sfd, SOL_XDP, XDP_UMEM_REG, &mr, sizeof(mr)) == 0);
    xassert(setsockopt(sfd, SOL_XDP, XDP_UMEM_FILL_RING, &fq_size, sizeof(int)) == 0);
    xassert(setsockopt(sfd, SOL_XDP, XDP_UMEM_COMPLETION_RING, &cq_size, sizeof(int)) == 0);
    xassert(getsockopt(sfd, SOL_XDP, XDP_MMAP_OFFSETS, &off, &optlen) == 0);
    umem->fq.map = mmap(0, off.fr.desc + FQ_NUM_DESCS * sizeof(uint64_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, sfd, XDP_UMEM_PGOFF_FILL_RING);
    xassert(umem->fq.map != MAP_FAILED);

    umem->fq.mask = FQ_NUM_DESCS - 1;
    umem->fq.size = FQ_NUM_DESCS;
    umem->fq.producer = umem->fq.map + off.fr.producer;
    umem->fq.consumer = umem->fq.map + off.fr.consumer;
    umem->fq.ring = umem->fq.map + off.fr.desc;
    umem->fq.cached_cons = FQ_NUM_DESCS;

    umem->cq.map = mmap(0, off.cr.desc + CQ_NUM_DESCS * sizeof(uint64_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, sfd, XDP_UMEM_PGOFF_COMPLETION_RING);
    xassert(umem->cq.map != MAP_FAILED);
    umem->cq.mask = CQ_NUM_DESCS - 1;
    umem->cq.size = CQ_NUM_DESCS;
    umem->cq.producer = umem->cq.map + off.cr.producer;
    umem->cq.consumer = umem->cq.map + off.cr.consumer;
    umem->cq.ring = umem->cq.map + off.cr.desc;

    umem->frames = bufs;
    umem->fd = sfd;

    return umem;
}

struct xdp_sock *xsk_configure(struct xdp_umem *umem, int ifindex) {
    static int ndescs = NUM_DESCS;

    struct xdp_sock *xsk = calloc(1, sizeof(struct xdp_sock));

    int sfd = socket(AF_XDP, SOCK_RAW, 0);
    xassert(sfd >= 0);

    xsk->sfd = sfd;
    xsk->outstanding_tx = 0;

    if (!umem) {
        xsk->umem = xdp_umem_configure(sfd);
    } else {
        xsk->umem = umem;
    }

    struct xdp_mmap_offsets off;
    socklen_t optlen = sizeof(off);

    xassert(setsockopt(sfd, SOL_XDP, XDP_RX_RING, &ndescs, sizeof(int)) == 0);
    xassert(setsockopt(sfd, SOL_XDP, XDP_TX_RING, &ndescs, sizeof(int)) == 0);
    xassert(getsockopt(sfd, SOL_XDP, XDP_MMAP_OFFSETS, &off, &optlen) == 0);
    xsk->rx.map = mmap(0, off.rx.desc + NUM_DESCS * sizeof(struct xdp_desc), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, sfd, XDP_PGOFF_RX_RING);
    xassert(xsk->rx.map != MAP_FAILED);
    if (!umem) {
        for (__u64 i = 0; i < NUM_DESCS * FRAME_SIZE; i += FRAME_SIZE) {
            umem_fill_to_kernel(&xsk->umem->fq, &i, 1);
        }
    }

    xsk->tx.map = mmap(0, off.tx.desc + NUM_DESCS * sizeof(struct xdp_desc), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, sfd, XDP_PGOFF_TX_RING);
    xassert(xsk->tx.map != MAP_FAILED);



	xsk->rx.mask = NUM_DESCS - 1;
	xsk->rx.size = NUM_DESCS;
	xsk->rx.producer = xsk->rx.map + off.rx.producer;
	xsk->rx.consumer = xsk->rx.map + off.rx.consumer;
	xsk->rx.ring = xsk->rx.map + off.rx.desc;

	xsk->tx.mask = NUM_DESCS - 1;
	xsk->tx.size = NUM_DESCS;
	xsk->tx.producer = xsk->tx.map + off.tx.producer;
	xsk->tx.consumer = xsk->tx.map + off.tx.consumer;
	xsk->tx.ring = xsk->tx.map + off.tx.desc;
	xsk->tx.cached_cons = NUM_DESCS;

    struct sockaddr_xdp sxdp = {};
	sxdp.sxdp_family = AF_XDP;
	sxdp.sxdp_ifindex = ifindex;
	sxdp.sxdp_queue_id = 0;

	if (umem) {
		sxdp.sxdp_flags = XDP_SHARED_UMEM;
		sxdp.sxdp_shared_umem_fd = umem->fd;
	} else {
		sxdp.sxdp_flags = 0;
	}

	xassert(bind(sfd, (struct sockaddr *)&sxdp, sizeof(sxdp)) == 0);

	return xsk;
}

void load_skb_program(const char *ifname, int ifindex, int xsk_map_fd, int a2s_info_cache_map_fd) {
    a2s_cache_map_fd = a2s_info_cache_map_fd;
    xassert(pthread_mutex_init(&a2s_cache_lock, NULL) == 0);

    int num_cpus = get_nprocs_conf();
    if (num_cpus > MAX_CPUS) {
        num_cpus = MAX_CPUS;
    }
    for (int cpu_id = 0; cpu_id < num_cpus; cpu_id++) {
        struct xdp_sock *xsk = xsk_configure(NULL, ifindex);
        xassert(bpf_map_update_elem(xsk_map_fd, &cpu_id, &xsk->sfd, BPF_ANY) == 0);
        xsk_cache_run(xsk);
    }
}
