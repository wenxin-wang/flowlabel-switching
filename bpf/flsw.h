#ifndef __FLSW_H__
#define __FLSW_H__

#include "bpf_helpers.h"

#include <arpa/inet.h>
#include <linux/ipv6.h>
#include <stddef.h>

#define MAX_LABEL_MAPS 256
#define MAX_LABEL_ENTRIES 256
#define MAX_INTFS 256

#define MAX_LABEL ((1 << 20) - 1)

#define FLOWLABEL_OFF offsetof(struct ipv6hdr, flow_lbl)

#define FLSW_ROUTING_HDR_TYPE 252

#define IPV6_FLOWLABEL_MASK __constant_htonl(0x000FFFFFU)
#define IPV6_FLOWINFO_MASK __constant_htonl(0x0FFFFFFF)
#define IPV6_MULTICAST_MASK __constant_htons(0xFFC0)
#define IPV6_MULTICAST_PREF __constant_htons(0xFE80)
#define IPV6_LINKLOCAL_MASK __constant_htons(0xFF00)
#define IPV6_LINKLOCAL_PREF __constant_htons(0xFF00)

enum flsw_mode {
	FLSW_MODE_INLINE,
	FLSW_MODE_ENCAP,
	FLSW_MODE_SEGMENT,
};

struct flsw_hdr {
	__u8 nexthdr;
	__u8 hdrlen;
	__u8 type;
	__u8 segments_left;
	__u32 unused;
};

struct flsw_overhead {
	struct ipv6hdr hdr6;
	struct flsw_hdr iflsw;
};

#define FLSW_ENCAP_OVERHEAD (sizeof(struct flsw_overhead))

struct nexthop_info {
	struct in6_addr nexthop;
	__u32 label;
};

static __always_inline void set_flowlabel(__u8 flow_lbl[3], __u32 label) {
  	flow_lbl[0] = (0xF0 & flow_lbl[0]) | (0x0F & (label >> 16));
	flow_lbl[1] = (__u8)(label >> 8);
	flow_lbl[2] = (__u8)label;
}

static __always_inline void clear_flowlabel(__u8 flow_lbl[3]) {
	flow_lbl[0] = (0xF0 & flow_lbl[0]);
	flow_lbl[1] = 0;
	flow_lbl[2] = 0;
}

static __always_inline void ip6h_set_flowlabel(struct ipv6hdr *ip6h, __u32 label)
{
  	__be32 nlabel;
	nlabel = __constant_htonl(label) & IPV6_FLOWLABEL_MASK;
	*(__be32 *)ip6h = (*(__be32 *)ip6h & ~IPV6_FLOWLABEL_MASK) | nlabel;
}

static __always_inline void ip6h_clear_flowlabel(struct ipv6hdr *ip6h)
{
	*(__be32 *)ip6h &= ~IPV6_FLOWLABEL_MASK;
}

static __always_inline void init_flsw_hdr(struct flsw_hdr *iflsw_hdr)
{
	iflsw_hdr->nexthdr = IPPROTO_IPV6;
	iflsw_hdr->hdrlen = 0;
	iflsw_hdr->type = FLSW_ROUTING_HDR_TYPE;
	iflsw_hdr->segments_left = 0;
	iflsw_hdr->unused = 0;
}

static __always_inline void
	init_flsw_overhead(struct flsw_overhead *overhead,
			   const struct nexthop_info *pnh_info,
			   enum flsw_mode mode)
{
	init_flsw_hdr(&overhead->iflsw);
	overhead->hdr6.nexthdr = IPPROTO_ROUTING;
	overhead->hdr6.payload_len = __constant_htons(
		__constant_ntohs(overhead->hdr6.payload_len) +
		FLSW_ENCAP_OVERHEAD); // flsw_hdr + original ipv6 hdr
	if (mode == FLSW_MODE_SEGMENT) {
		overhead->hdr6.daddr = pnh_info->nexthop;
	}
}

#endif
