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
#include <sys/mman.h>
#include <unistd.h>
#include <sys/resource.h>
#include <stdlib.h>
#include <pthread.h>
#include <linux/bpf.h>
#include <linux/bpf_common.h>

#include "bpf_load.h"

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

#define xassert(expr)							\
    if (!(expr)) {						\
        fprintf(stderr, "%s:%s:%i: Assertion failed: "	\
            #expr ": errno: %d/\"%s\"\n",		\
            __FILE__, __func__, __LINE__,		\
            errno, strerror(errno));		\
        exit(EXIT_FAILURE);				\
    }							\

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

static inline int umem_nb_free(struct xdp_umem_uqueue *q, uint32_t nb) {
    uint32_t free_entries = q->cached_cons - q->cached_prod;

    if (free_entries >= nb) {
        return free_entries;
    }

    barrier();
    q->cached_cons = *q->consumer + q->size;

    return q->cached_cons - q->cached_prod;
}

static inline int umem_fill_to_kernel(struct xdp_umem_uqueue *fq, uint64_t *d, size_t nb) {
    if (umem_nb_free(fq, nb) < nb) {
        return -ENOSPC;
    }

    for (uint32_t i = 0; i < nb; i++) {
        uint32_t idx = fq->cached_prod++ & fq->mask;

        fq->ring[idx] = d[i];
    }

    *fq->producer = fq->cached_prod;

    return 0;
}

struct xdp_umem *xdp_umem_configure(int sfd) {
    int fq_size = FQ_NUM_DESCS, cq_size = CQ_NUM_DESCS;
    struct xdp_mmap_offsets off;
    socklen_t optlen = sizeof(off);
    struct xdp_umem_reg mr;

    struct xdp_umem *umem = calloc(1, sizeof(struct xdp_umem));
    void *bufs;
    posix_memalign(&bufs, getpagesize(), NUM_FRAMES * FRAME_SIZE);

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
        for (uint64_t i = 0; i < NUM_DESCS * FRAME_SIZE; i += FRAME_SIZE) {
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
		sxdp.sxdp_flags = XDP_COPY;
	}

	xassert(bind(sfd, (struct sockaddr *)&sxdp, sizeof(sxdp)) == 0);

	return xsk;
}

int load_skb_program(const char *ifname, int ifindex, int xsk_map_fd) {
    struct xdp_sock *xsk = xsk_configure(NULL, ifindex);
    return 0;
}