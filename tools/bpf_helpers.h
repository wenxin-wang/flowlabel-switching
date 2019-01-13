#ifndef __TOOLS_BPF_H__
#define __TOOLS_BPF_H__

#include <linux/bpf.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <string.h>

#define ptr_to_u64(ptr)	((__u64)(unsigned long)(ptr))

static inline int sys_bpf(
    enum bpf_cmd cmd, union bpf_attr *attr,
    unsigned int size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}

static inline int bpf_obj_get(const char *pathname)
{
    union bpf_attr attr;

    memset(&attr, 0, sizeof(attr));
    attr.pathname = ptr_to_u64((void *)pathname);

    return sys_bpf(BPF_OBJ_GET, &attr, sizeof(attr));
}

static inline int bpf_map_update_elem(int fd, const void *key, const void *value,
__u64 flags)
{
    union bpf_attr attr;

    memset(&attr, 0, sizeof(attr));
    attr.map_fd = fd;
    attr.key = ptr_to_u64(key);
    attr.value = ptr_to_u64(value);
    attr.flags = flags;

    return sys_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

static inline int bpf_map_delete_elem(int fd, const void *key)
{
	union bpf_attr attr;

	bzero(&attr, sizeof(attr));
	attr.map_fd = fd;
	attr.key = ptr_to_u64(key);

	return sys_bpf(BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
}

#endif
