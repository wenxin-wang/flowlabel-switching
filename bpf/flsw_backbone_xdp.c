#include "flsw_backbone_xdp.h"

#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <arpa/inet.h>

// Flowlabel is 12-31 bit of an ipv6 header (20 bits),
// but lwt xmit bpf can only load and store bytes.
// So load 3 bytes, change the flowlabel part,
// and store them back.
// Kernel does the same trick with struct ipv6hdr's flow_lbl field

#define IPV6_FLOWINFO_MASK		0x0FFFFFFF
#define IPV6_FLOWLABEL_MASK		0x000FFFFF

#define IPV6_MULTICAST_MASK __constant_htons(0xFFC0)
#define IPV6_MULTICAST_PREF __constant_htons(0xFE80)
#define IPV6_LINKLOCAL_MASK __constant_htons(0xFF00)
#define IPV6_LINKLOCAL_PREF __constant_htons(0xFF00)

struct bpf_elf_map flsw_backbone_nexthop_map __section("maps") = {
    .id             = 1,
    .type           = BPF_MAP_TYPE_HASH,
    .size_key       = sizeof(__u32),
    .size_value     = sizeof(struct nexthop_info),
    .pinning        = PIN_GLOBAL_NS,
    .max_elem       = MAX_LABEL_ENTRIES,
	.flags          = BPF_F_NO_PREALLOC,
};

struct bpf_elf_map flsw_backbone_intf_map __section("maps") = {
	.type           = BPF_MAP_TYPE_HASH,
	.size_key       = sizeof(__u32),
	.size_value     = sizeof(__u32),
    .pinning        = PIN_GLOBAL_NS,
	.max_elem       = MAX_INTFS,
};

struct bpf_elf_map flsw_backbone_nexthop_maps __section("maps") = {
	.type           = BPF_MAP_TYPE_ARRAY_OF_MAPS,
	.size_key       = sizeof(__u32),
    .size_value     = sizeof(__u32), // seems that all map_in_map's have this value size
	.inner_id       = 1,
    .pinning        = PIN_GLOBAL_NS,
	.max_elem       = MAX_LABEL_MAPS,
};

static __always_inline void unset_flowlabel(struct ipv6hdr *ip6h)
{
    *(__u32 *)ip6h &= __constant_htonl(!IPV6_FLOWLABEL_MASK);
}

static __always_inline int do_redirect_v6(
    struct xdp_md *ctx, struct ethhdr *eth, struct ipv6hdr *ip6h,
    struct bpf_elf_map *nexthop_map,
    __u32 olabel, __u64 flags)
{
	struct bpf_fib_lookup fib_params;
    struct in6_addr *src, *dst;
    struct nexthop_info *pnhop;
    __u32 nlabel;
	int ret;

    pnhop = map_lookup_elem(nexthop_map, &olabel);
    if (!pnhop) {
        // All unknown label must be cleared
        unset_flowlabel(ip6h);
        return XDP_PASS;
    }

    __builtin_memset(&fib_params, 0, sizeof(fib_params));
    fib_params.family	= AF_INET6;

    nlabel = (pnhop->label &= IPV6_FLOWLABEL_MASK);
    *(__u32 *)ip6h = ((*(__u32 *)ip6h) & __constant_htonl(!IPV6_FLOWLABEL_MASK)) |
        __constant_htonl(nlabel);
    fib_params.flowinfo		= __constant_htonl(nlabel);
    fib_params.l4_protocol	= ip6h->nexthdr;
    fib_params.sport	= 0;
    fib_params.dport	= 0;
    fib_params.tot_len	= __constant_ntohs(ip6h->payload_len);
    src		= (struct in6_addr *) fib_params.ipv6_src;
    dst		= (struct in6_addr *) fib_params.ipv6_dst;
    *src	= ip6h->saddr;
    *dst	= pnhop->nexthop;

	fib_params.ifindex = ctx->ingress_ifindex;

	ret = fib_lookup(ctx, &fib_params, sizeof(fib_params), flags);

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
		return redirect(fib_params.ifindex, 0);
	}

	return XDP_PASS;
}

static __always_inline int is_multicast_or_ll(struct ipv6hdr *ip6h)
{
    __be16 a = ip6h->daddr.in6_u.u6_addr16[0];
    return (a & IPV6_MULTICAST_MASK) == IPV6_MULTICAST_PREF ||
        (a & IPV6_LINKLOCAL_MASK) == IPV6_LINKLOCAL_PREF;
}

static __always_inline int do_flsw_backbone(
    struct xdp_md *ctx, struct bpf_elf_map *nexthop_map, __u64 flags)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
    struct ipv6hdr *ip6h;
    __u32 olabel;

    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

	if (eth->h_proto != __constant_htons(ETH_P_IPV6))
        return XDP_PASS;

    ip6h = data + sizeof(*eth);
    if ((void*)(ip6h + 1) > data_end)
        return XDP_PASS;

    if (ip6h->hop_limit <= 1 || is_multicast_or_ll(ip6h))
        return XDP_PASS;

    olabel = __constant_ntohl(*(__be32*)ip6h) & IPV6_FLOWLABEL_MASK;

    return do_redirect_v6(ctx, eth, ip6h, nexthop_map, olabel, flags);
}

__section("fwd")
int do_fwd(struct xdp_md *ctx)
{
    return do_flsw_backbone(ctx, &flsw_backbone_nexthop_map, 0);
}

__section("fwd-rtdirect")
int do_fwd_rtdirect(struct xdp_md *ctx)
{
    return do_flsw_backbone(ctx, &flsw_backbone_nexthop_map, BPF_FIB_LOOKUP_DIRECT);
}

__section("mtfwd")
int do_mtfwd(struct xdp_md *ctx)
{
    __u32 *map_id;
    struct bpf_elf_map *nexthop_map;
    map_id = map_lookup_elem(&flsw_backbone_intf_map, &ctx->ingress_ifindex);
    if (!map_id)
        return XDP_PASS;
    nexthop_map = map_lookup_elem(&flsw_backbone_nexthop_maps, map_id);
    if (!nexthop_map)
        return XDP_PASS;

    return do_flsw_backbone(ctx, nexthop_map, 0);
}

char __license[] __section("license") = "GPL";
