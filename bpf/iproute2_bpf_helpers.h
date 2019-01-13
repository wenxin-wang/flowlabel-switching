/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __IPROUTE2_BPF_HELPERS_H
#define __IPROUTE2_BPF_HELPERS_H

#include <linux/bpf.h>
#include <iproute2/bpf_elf.h>

#ifndef __section
# define __section(NAME)                        \
    __attribute__((section(NAME), used))
#endif

#ifndef __section_tail
# define __section_tail(ID, KEY)                    \
    __section(__stringify(ID) "/" __stringify(KEY))
#endif

#ifndef __inline
# define __inline                               \
    inline __attribute__((always_inline))
#endif

#ifndef lock_xadd
# define lock_xadd(ptr, val)                    \
    ((void)__sync_fetch_and_add(ptr, val))
#endif

#ifndef BPF_FUNC
# define BPF_FUNC(NAME, ...)                        \
    (*NAME)(__VA_ARGS__) = (void *)BPF_FUNC_##NAME
#endif

#endif
