#include "bpf_kern_common.h"
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/bpf_common.h>
#include <stdint.h>

#include "config.h"

SEC("socket")
int cache_socket(struct __sk_buff *skb) {
    return SK_PASS;
}