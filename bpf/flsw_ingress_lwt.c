#include "flsw_ingress_lwt.h"

#include <stddef.h>
#include <linux/if_ether.h>
#include <linux/icmpv6.h>

// Flowlabel is 12-31 bit of an ipv6 header (20 bits),
// but lwt xmit bpf can only load and store bytes.
// So load 3 bytes, change the flowlabel part,
// and store them back.
// Kernel does the same trick with struct ipv6hdr's flow_lbl field

#define FLOWLABEL_OFF offsetof(struct ipv6hdr, flow_lbl)
#define DADDR_OFF offsetof(struct ipv6hdr, daddr)
#define NEXTHDR_OFF offsetof(struct ipv6hdr, nexthdr)

struct bpf_elf_map flsw_ingress_lpm_map __section("maps") = {
	// .id             = 1,
	.type = BPF_MAP_TYPE_LPM_TRIE,
	.size_key = sizeof(struct lpm_key_6),
	.size_value = sizeof(struct nexthop_info),
	.pinning = PIN_GLOBAL_NS,
	.max_elem = MAX_LABEL_ENTRIES,
	.flags = BPF_F_NO_PREALLOC,
};

static __always_inline int set_label(struct __sk_buff *skb, __u32 label)
{
	__u8 flow_lbl[3];
	int ret;

	ret = skb_load_bytes(skb, FLOWLABEL_OFF, flow_lbl, 3);
	if (unlikely(ret < 0)) {
		return BPF_OK;
	}

	set_flowlabel(flow_lbl, label);
	ret = skb_store_bytes(skb, FLOWLABEL_OFF, flow_lbl, 3, 0);
	if (unlikely(ret < 0)) {
		return BPF_OK;
	}

	return BPF_OK;
}

static __always_inline int ingress_fwd(struct __sk_buff *skb,
				       const struct nexthop_info *pnh_info,
				       enum flsw_mode mode)
{
	int ret;
	struct flsw_overhead overhead;
	if (mode == FLSW_MODE_INLINE)
		return set_label(skb, pnh_info ? pnh_info->label : 0);
	else if (!pnh_info || !pnh_info->label) {// do nothing if label not found or empty
		return BPF_OK;
	}

	ret = skb_load_bytes(skb, 0, &overhead.hdr6, sizeof(overhead.hdr6));
	if (unlikely(ret < 0)) {
		return BPF_OK;
	}

	init_flsw_overhead(&overhead, pnh_info, mode);

	ret = lwt_push_encap(skb, BPF_LWT_ENCAP_IP, &overhead, FLSW_ENCAP_OVERHEAD);
	if (unlikely(ret < 0)) {
		return BPF_DROP;
	}
	return set_label(skb, pnh_info->label);
}

static __always_inline int lpm_label(struct __sk_buff *skb,
				     struct bpf_elf_map *label_map,
				     enum flsw_mode mode)
{
	__u8 nexthdr;
	struct lpm_key_6 key6;
	struct nexthop_info *pnh_info;
	int ret;

	ret = skb_load_bytes(skb, NEXTHDR_OFF, &nexthdr, sizeof(nexthdr));
	if (unlikely(ret < 0)) {
		return BPF_OK;
	}

	if (mode != FLSW_MODE_INLINE && nexthdr == IPPROTO_ICMPV6) {
		__u8 icmp6_type;
		ret = skb_load_bytes(skb, sizeof(struct ipv6hdr), &icmp6_type, sizeof(icmp6_type));
		if (unlikely(ret < 0)) {
			return BPF_OK;
		}
		if (!(icmp6_type == ICMPV6_ECHO_REQUEST) &&
		    !(icmp6_type == ICMPV6_ECHO_REPLY)) {
			return BPF_OK;
		}
	}

	ret = skb_load_bytes(skb, DADDR_OFF, &key6.addr, sizeof(key6.addr));
	if (unlikely(ret < 0)) {
		return BPF_OK;
	}

	key6.prefixlen = 128;
	pnh_info = map_lookup_elem(label_map, &key6);
	return ingress_fwd(skb, pnh_info, mode);
}

static __always_inline int do_lpm_label(struct __sk_buff *skb, enum flsw_mode mode)
{
	if (skb->protocol != __constant_htons(ETH_P_IPV6)) {
		return BPF_OK;
	}
	return lpm_label(skb, &flsw_ingress_lpm_map, mode);
}

__section("lpm-inline") int do_lpm_label_inline(struct __sk_buff *skb)
{
	return do_lpm_label(skb, FLSW_MODE_INLINE);
}

__section("lpm-encap") int do_lpm_label_encap(struct __sk_buff *skb)
{
	return do_lpm_label(skb, FLSW_MODE_ENCAP);
}

__section("lpm-segment") int do_lpm_label_segment(struct __sk_buff *skb)
{
	return do_lpm_label(skb, FLSW_MODE_SEGMENT);
}

__section("fwmk-inline") int do_labelfwmk(struct __sk_buff *skb)
{
	if (skb->protocol != __constant_htons(ETH_P_IPV6))
		return BPF_OK;
	return set_label(skb, skb->mark);
}

__section("unlabel") int do_unlabel(struct __sk_buff *skb)
{
	__u8 flow_lbl[3];
	if (skb->protocol != __constant_htons(ETH_P_IPV6))
		return BPF_OK;

	skb_load_bytes(skb, FLOWLABEL_OFF, flow_lbl, 1);
	clear_flowlabel(flow_lbl);
	skb_store_bytes(skb, FLOWLABEL_OFF, flow_lbl, 3, 0);

	return BPF_OK;
}

char __license[] __section("license") = "GPL";
