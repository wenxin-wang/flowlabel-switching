#ifndef __FLSW_BACKBONE_XDP_H__
#define __FLSW_BACKBONE_XDP_H__

#include "flsw.h"

struct nexthop_info {
	struct in6_addr nexthop;
	__u32 label;
};

#endif
