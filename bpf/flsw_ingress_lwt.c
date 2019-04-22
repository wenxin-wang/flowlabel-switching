#include "flsw_ingress_lwt.h"

#include <stddef.h>
#include <linux/if_ether.h>

// Flowlabel is 12-31 bit of an ipv6 header (20 bits),
// but lwt xmit bpf can only load and store bytes.
// So load 3 bytes, change the flowlabel part,
// and store them back.
// Kernel does the same trick with struct ipv6hdr's flow_lbl field

#define FLOWLABEL_OFF offsetof(struct ipv6hdr, flow_lbl)
#define DADDR_OFF offsetof(struct ipv6hdr, daddr)

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
		printk("8: %d\n", ret);
		return BPF_OK;
	}

	flow_lbl[0] = (0xF0 & flow_lbl[0]) | (0x0F & (label >> 16));
	flow_lbl[1] = (__u8)(label >> 8);
	flow_lbl[2] = (__u8)label;
	ret = skb_store_bytes(skb, FLOWLABEL_OFF, flow_lbl, 3, 0);
	if (unlikely(ret < 0)) {
		printk("9: %d\n", ret);
		return BPF_OK;
	}

	printk("10: FFFFFF\n");
	return BPF_OK;
}

static __always_inline int ingress_fwd(struct __sk_buff *skb,
				       const struct nexthop_info *pnh_info,
				       enum flsw_mode mode)
{
	int ret;
	struct ipv6hdr nhdr6;
	struct flsw_hdr iflsw_hdr;
	if (mode == FLSW_MODE_INLINE)
		return set_label(skb, pnh_info ? pnh_info->label : 0);
	else if (!pnh_info || !pnh_info->label) {// do nothing if label not found or empty
		printk("7\n");
		return BPF_OK;
	}

	ret = skb_load_bytes(skb, 0, &nhdr6, sizeof(nhdr6));
	if (unlikely(ret < 0)) {
		printk("3: %d\n", ret);
		return BPF_OK;
	}
	ret = skb_change_head(skb, FLSW_ENCAP_OVERHEAD, 0);
	if (unlikely(ret)) {
		printk("4: %d\n", ret);
		return BPF_OK; // assumes that skb is left unchanged
	}
	// now skb->data and mac_header points to pushed position
	// MAYBUG: network_header is left unchanged

	init_flsw_overhead(&nhdr6, &iflsw_hdr, pnh_info, mode);
	ret = skb_store_bytes(skb, 0, &nhdr6, sizeof(nhdr6), 0);
	if (unlikely(ret < 0)) {
		printk("5: %d\n", ret);
		return BPF_DROP;
	}
	ret = skb_store_bytes(skb, sizeof(nhdr6), &iflsw_hdr, sizeof(iflsw_hdr), 0);
	if (unlikely(ret < 0)) {
		printk("6: %d\n", ret);
		return BPF_DROP;
	}
	return set_label(skb, pnh_info->label);
}

static __always_inline int lpm_label(struct __sk_buff *skb,
				     struct bpf_elf_map *label_map,
				     enum flsw_mode mode)
{
	struct lpm_key_6 key6;
	struct nexthop_info *pnh_info;
	int ret;

	ret = skb_load_bytes(skb, DADDR_OFF, &key6.addr, sizeof(key6.addr));
	if (unlikely(ret < 0)) {
		printk("2: %d\n", ret);
		return BPF_OK;
	}

	key6.prefixlen = 128;
	pnh_info = map_lookup_elem(label_map, &key6);
	return ingress_fwd(skb, pnh_info, mode);
}

static __always_inline int do_lpm_label(struct __sk_buff *skb, enum flsw_mode mode)
{
	if (skb->protocol != __constant_htons(ETH_P_IPV6)) {
		printk("IIPJIPOIPJIJP %d\n", __constant_ntohs(skb->protocol));
		return BPF_OK;
	}
	printk("1 %d\n", __constant_ntohs(skb->protocol));
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

	flow_lbl[0] = (0xF0 & flow_lbl[0]);
	flow_lbl[1] = 0;
	flow_lbl[2] = 0;
	skb_store_bytes(skb, FLOWLABEL_OFF, flow_lbl, 3, 0);

	return BPF_OK;
}

char __license[] __section("license") = "GPL";
