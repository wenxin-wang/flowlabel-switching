#include "flsw_backbone_xdp.h"

#include <linux/if_ether.h>

#ifdef USE_XDPCAP
static __always_inline enum xdp_action xdpcap_exit(struct xdp_md *ctx,
						   struct bpf_elf_map *hook,
						   enum xdp_action action)
{
	tail_call((void *)ctx, hook, action);
	return action;
}
#endif

struct bpf_elf_map flsw_backbone_nexthop_map __section("maps") = {
	// .id             = 1,
	.type = BPF_MAP_TYPE_HASH,
	.size_key = sizeof(__u32),
	.size_value = sizeof(struct nexthop_info),
	.pinning = PIN_GLOBAL_NS,
	.max_elem = MAX_LABEL_ENTRIES,
	.flags = BPF_F_NO_PREALLOC,
};

#ifdef USE_XDPCAP
struct bpf_elf_map xdpcap_pop_hook __section("maps") = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.size_key = sizeof(int),
	.size_value = sizeof(int),
	.max_elem = 5, // The max value of XDP_* constants
	.pinning = PIN_GLOBAL_NS,
};

struct bpf_elf_map xdpcap_redir_hook __section("maps") = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.size_key = sizeof(int),
	.size_value = sizeof(int),
	.max_elem = 5, // The max value of XDP_* constants
	.pinning = PIN_GLOBAL_NS,
};
#endif

static __always_inline int pop_to_native_stack(struct xdp_md *ctx,
					       struct ethhdr *eth,
					       struct ipv6hdr *ip6h,
					       enum flsw_mode mode)
{
	struct ethhdr oeth;
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	if (mode == FLSW_MODE_INLINE) {
		ip6h_clear_flowlabel(ip6h);
#ifdef USE_XDPCAP
		return xdpcap_exit(ctx, &xdpcap_pop_hook, XDP_PASS);
#else
		return XDP_PASS;
#endif
	}
        if (data + FLSW_ENCAP_OVERHEAD + sizeof(oeth) > data_end) {
#ifdef USE_XDPCAP
		return xdpcap_exit(ctx, &xdpcap_pop_hook, XDP_PASS);
#else
		return XDP_PASS;
#endif
	}
	oeth = *eth;
	xdp_adjust_head(ctx, FLSW_ENCAP_OVERHEAD);
	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(oeth) > data_end)
		return XDP_PASS;
	__builtin_memcpy(data, &oeth, sizeof(oeth));
#ifdef USE_XDPCAP
	return xdpcap_exit(ctx, &xdpcap_pop_hook, XDP_PASS);
#else
	return XDP_PASS;
#endif
}

static __always_inline int do_redirect_v6(struct xdp_md *ctx,
					  struct ethhdr *eth,
					  struct ipv6hdr *ip6h,
					  struct nexthop_info *pnhop,
					  enum flsw_mode mode, __u64 rt_flags)
{
	struct bpf_fib_lookup fib_params;
	struct in6_addr *src, *dst;
	int ret;

	__builtin_memset(&fib_params, 0, sizeof(fib_params));
	fib_params.family = AF_INET6;

	ip6h_set_flowlabel(ip6h, pnhop->label);

	fib_params.flowinfo = *(__be32 *)ip6h & IPV6_FLOWINFO_MASK;
	fib_params.l4_protocol = ip6h->nexthdr;
	fib_params.sport = 0;
	fib_params.dport = 0;
	fib_params.tot_len = __constant_ntohs(ip6h->payload_len);
	src = (struct in6_addr *)fib_params.ipv6_src;
	dst = (struct in6_addr *)fib_params.ipv6_dst;
	*src = ip6h->saddr;
	*dst = pnhop->nexthop;

	fib_params.ifindex = ctx->ingress_ifindex;

	ret = fib_lookup(ctx, &fib_params, sizeof(fib_params), rt_flags);

	/* verify egress index has xdp support
   * TO-DO bpf_map_lookup_elem(&tx_port, &key) fails with
   *       cannot pass map_type 14 into func bpf_map_lookup_elem#1:
   * NOTE: without verification that egress index supports XDP
   *       forwarding packets are dropped.
   */
	if (ret == 0) {
		ip6h->hop_limit--;

		__builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
		__builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
		ret = redirect(fib_params.ifindex, 0);
#ifdef USE_XDPCAP
		return xdpcap_exit(ctx, &xdpcap_redir_hook, ret);
#else
		return ret;
#endif
	}

	return pop_to_native_stack(ctx, eth, ip6h, mode);
}

static __always_inline int is_multicast_or_ll(struct ipv6hdr *ip6h)
{
	__be16 a = ip6h->daddr.s6_addr16[0];
	return (a & IPV6_MULTICAST_MASK) == IPV6_MULTICAST_PREF ||
	       (a & IPV6_LINKLOCAL_MASK) == IPV6_LINKLOCAL_PREF;
}

static __always_inline int do_flsw_backbone(struct xdp_md *ctx,
					    struct bpf_elf_map *nexthop_map,
					    enum flsw_mode mode,
					    __u64 rt_flags)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct nexthop_info *pnhop;
	struct ethhdr *eth = data;
	struct ipv6hdr *ip6h;
	__u32 olabel;

	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	if (eth->h_proto != __constant_htons(ETH_P_IPV6))
		return XDP_PASS;

	ip6h = data + sizeof(*eth);
	if ((void *)(ip6h + 1) > data_end)
		return XDP_PASS;

	// normal ipv6 packets are pass through
	if (mode != FLSW_MODE_INLINE && ip6h->nexthdr != IPPROTO_ROUTING)
		return XDP_PASS;

	if (ip6h->hop_limit <= 1 || is_multicast_or_ll(ip6h)) {
		return pop_to_native_stack(ctx, eth, ip6h, mode);
	}

	olabel = __constant_ntohl(*(__be32 *)ip6h & IPV6_FLOWLABEL_MASK);
	pnhop = map_lookup_elem(nexthop_map, &olabel);
	if (!pnhop || !pnhop->label) {
		// unknown label or empty label
		return pop_to_native_stack(ctx, eth, ip6h, mode);
	}

	return do_redirect_v6(ctx, eth, ip6h, pnhop, mode, rt_flags);
}

__section("inline") int do_inline(struct xdp_md *ctx)
{
  return do_flsw_backbone(ctx, &flsw_backbone_nexthop_map, FLSW_MODE_INLINE, 0);
}

__section("encap") int do_encap(struct xdp_md *ctx)
{
  return do_flsw_backbone(ctx, &flsw_backbone_nexthop_map, FLSW_MODE_ENCAP, 0);
}

__section("segment") int do_segment(struct xdp_md *ctx)
{
  return do_flsw_backbone(ctx, &flsw_backbone_nexthop_map, FLSW_MODE_SEGMENT, 0);
}

__section("inline-rtdirect") int do_inline_rtdirect(struct xdp_md *ctx)
{
	return do_flsw_backbone(ctx, &flsw_backbone_nexthop_map,
				FLSW_MODE_INLINE, BPF_FIB_LOOKUP_DIRECT);
}

__section("encap-rtdirect") int do_encap_rtdirect(struct xdp_md *ctx)
{
	return do_flsw_backbone(ctx, &flsw_backbone_nexthop_map,
				FLSW_MODE_ENCAP, BPF_FIB_LOOKUP_DIRECT);
}

__section("segment-rtdirect") int do_segment_rtdirect(struct xdp_md *ctx)
{
	return do_flsw_backbone(ctx, &flsw_backbone_nexthop_map,
				FLSW_MODE_SEGMENT, BPF_FIB_LOOKUP_DIRECT);
}

char __license[] __section("license") = "GPL";
