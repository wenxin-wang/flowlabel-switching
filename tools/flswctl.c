#include "../bpf/flsw_lwt.h"

#include <bcc/libbpf.h>

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#include <errno.h>

#define ptr_to_u64(ptr)	((__u64)(unsigned long)(ptr))

int del_label() {
    int fd = bpf_obj_get("/sys/fs/bpf/ip/globals/flsw_lpm_label_map");
    printf("bpf: get fd:%d (%s)\n", fd, strerror(errno));
    struct lpm_key_6 prefix;
    prefix.prefixlen = 32;
    prefix.addr.s6_addr32[0] = htonl(0xfdde0000);
    prefix.addr.s6_addr32[1] = 0;
    prefix.addr.s6_addr32[2] = 0;
    prefix.addr.s6_addr32[3] = 0;
    bpf_delete_elem(fd, &prefix);
    return 0;
}

int add_lpm_label(const char* path, __u32 label) {
    int fd;
    struct lpm_key_6 prefix;
    fd = bpf_obj_get(path);
    printf("bpf: get fd:%d (%s)\n", fd, strerror(errno));
    prefix.prefixlen = 32;
    prefix.addr.s6_addr32[0] = htonl(0xfdde0000);
    prefix.addr.s6_addr32[1] = 0;
    prefix.addr.s6_addr32[2] = 0;
    prefix.addr.s6_addr32[3] = 0;
    bpf_update_elem(fd, &prefix, &label, BPF_ANY);
    return 0;
}

int add_lpm_label_map(unsigned id) {
    const char* filename = "/sys/fs/bpf/ip/globals/flsw_lpm_label_maps";
    int maps_fd = bpf_obj_get(filename), fd;
    int ret;
    printf("bpf: get %s fd:%d (%s)\n", filename, maps_fd, strerror(errno));

    fd = bpf_create_map(
        BPF_MAP_TYPE_LPM_TRIE, "fck",
        sizeof(struct lpm_key_6), sizeof(__u32),
        MAX_LABEL_ENTRIES, BPF_F_NO_PREALLOC);
    if (fd < 0) {
        printf("WFF %d %s\n", fd, strerror(errno));
        exit(-1);
    }
    ret = bpf_obj_pin(fd, "/sys/fs/bpf/fck");
    if (ret < 0) {
        printf("Pin failed %d %s\n", ret, strerror(errno));
        close(fd);
        exit(-1);
    }

    ret = bpf_update_elem(maps_fd, &id, &fd, BPF_ANY);
    if (ret < 0) {
        printf("WTF %d %s\n", ret, strerror(errno));
        close(fd);
        exit(-1);
    }

    return 0;
}

int main() {
    // return add_lpm_label_map(0);
    add_lpm_label("/sys/fs/bpf/ip/globals/flsw_lpm_label_map", 0xa8);
    return add_lpm_label("/sys/fs/bpf/fck", 0x9c);
}
