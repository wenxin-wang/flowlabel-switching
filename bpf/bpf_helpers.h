/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __IPROUTE2_BPF_HELPERS_H
#define __IPROUTE2_BPF_HELPERS_H

#include <bcc/compat/linux/bpf.h>
#include <iproute2/bpf_elf.h>

#ifndef __section
#define __section(NAME) __attribute__((section(NAME), used))
#endif

#ifndef __section_tail
#define __section_tail(ID, KEY) __section(__stringify(ID) "/" __stringify(KEY))
#endif

#ifndef __inline
#define __inline inline __attribute__((always_inline))
#endif

#ifndef lock_xadd
#define lock_xadd(ptr, val) ((void)__sync_fetch_and_add(ptr, val))
#endif

#ifndef BPF_FUNC
#define BPF_FUNC(NAME, ...) (*NAME)(__VA_ARGS__) = (void *)BPF_FUNC_##NAME
#endif

#ifndef BIT
#define BIT(nr) (1UL << (nr))
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

static int BPF_FUNC(skb_load_bytes, const struct __sk_buff *skb, __u32 offset,
		      void *to, __u32 len);
static int BPF_FUNC(skb_store_bytes, struct __sk_buff *skb, __u32 offset,
		      void *from, __u32 len, __u64 flags);
static void *BPF_FUNC(map_lookup_elem, void *map, const void *key);
static int BPF_FUNC(fib_lookup, struct xdp_md *ctx,
		    struct bpf_fib_lookup *params, int plen, __u32 flags);
static int BPF_FUNC(redirect, __u32 key, __u64 flags);
static int BPF_FUNC(skb_change_head, const struct __sk_buff *skb,
		    __u32 head_room, __u64 flags);
static int BPF_FUNC(trace_printk, const char *fmt, int fmt_size, ...);

#define printk(fmt, ...)                                                       \
	({                                                                     \
		char ____fmt[] = fmt;                                          \
		trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);         \
	})

#endif
