#ifndef __FLSW_LWT_H__
#define __FLSW_LWT_H__

#define MAX_LABEL_MAPS 256
#define MAX_LABEL_ENTRIES 256

#include <linux/ipv6.h>

struct lpm_key_6 {
	__u32	prefixlen;     // Always set to 128 for looking up
    struct in6_addr addr;
};

#endif
