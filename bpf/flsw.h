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
#define FLSW_ENCAP_OVERHEAD (sizeof(struct ipv6hdr) + sizeof(struct flsw_hdr))

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

struct nexthop_info {
	struct in6_addr nexthop;
	__u32 label;
};

static inline void init_flsw_hdr(struct flsw_hdr *iflsw_hdr) {
  iflsw_hdr->nexthdr = IPPROTO_IPV6;
  iflsw_hdr->hdrlen = 0;
  iflsw_hdr->type = FLSW_ROUTING_HDR_TYPE;
  iflsw_hdr->segments_left = 0;
  iflsw_hdr->unused = 0;
}

static inline void init_flsw_overhead(struct ipv6hdr *nhdr6,
				      struct flsw_hdr *iflsw_hdr,
				      const struct nexthop_info *pnh_info,
				      enum flsw_mode mode)
{
	init_flsw_hdr(iflsw_hdr);
	nhdr6->nexthdr = IPPROTO_ROUTING;
	nhdr6->payload_len = __constant_htons(
		__constant_ntohs(nhdr6->payload_len) +
		FLSW_ENCAP_OVERHEAD); // flsw_hdr + original ipv6 hdr
	if (mode == FLSW_MODE_SEGMENT) {
		__builtin_memcpy(&nhdr6->daddr, &pnh_info->nexthop,
				 sizeof(nhdr6->daddr));
	}
}

#endif
