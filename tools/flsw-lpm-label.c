#include "bpf_helpers.h"

#include <linux/ipv6.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include <errno.h>

#define ptr_to_u64(ptr)	((__u64)(unsigned long)(ptr))


struct lpm_key_6 {
    __u32	prefixlen;     // Always set to 128 for looking up
    struct in6_addr addr;
};

int main() {
    int fd = bpf_obj_get("/sys/fs/bpf/ip/globals/flsw_lpm_label_map");
    printf("bpf: get fd:%d (%s)\n", fd, strerror(errno));
    __u32 label = 0x9a;
    struct lpm_key_6 prefix;
    prefix.prefixlen = 32;
    prefix.addr.s6_addr32[0] = htonl(0xfdde0000);
    prefix.addr.s6_addr32[1] = 0;
    prefix.addr.s6_addr32[2] = 0;
    prefix.addr.s6_addr32[3] = 0;
    bpf_map_delete_elem(fd, &prefix);
    return 0;
}
