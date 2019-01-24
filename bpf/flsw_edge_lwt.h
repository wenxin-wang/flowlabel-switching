#ifndef __FLSW_EDDGE_LWT_H__
#define __FLSW_EDDGE_LWT_H__

#include "flsw.h"
#include <linux/ipv6.h>

struct lpm_key_6 {
	__u32	prefixlen;     // Always set to 128 for looking up
    struct in6_addr addr;
};

#endif
