#include "flsw_edge_lwt.h"

#include <stddef.h>
#include <linux/if_ether.h>

// Flowlabel is 12-31 bit of an ipv6 header (20 bits),
// but lwt xmit bpf can only load and store bytes.
// So load 3 bytes, change the flowlabel part,
// and store them back.
// Kernel does the same trick with struct ipv6hdr's flow_lbl field

#define FLOWLABEL_OFF offsetof(struct ipv6hdr, flow_lbl)
#define DADDR_OFF offsetof(struct ipv6hdr, daddr)

struct bpf_elf_map flsw_edge_lpm_map __section("maps") = {
    .id             = 1,
    .type           = BPF_MAP_TYPE_LPM_TRIE,
    .size_key       = sizeof(struct lpm_key_6),
    .size_value     = sizeof(__u32),
    .pinning        = PIN_GLOBAL_NS,
    .max_elem       = MAX_LABEL_ENTRIES,
	.flags          = BPF_F_NO_PREALLOC,
};

struct bpf_elf_map flsw_edge_intf_map __section("maps") = {
	.type           = BPF_MAP_TYPE_HASH,
	.size_key       = sizeof(__u32),
	.size_value     = sizeof(__u32),
    .pinning        = PIN_GLOBAL_NS,
	.max_elem       = MAX_INTFS,
};

struct bpf_elf_map flsw_edge_lpm_maps __section("maps") = {
	.type           = BPF_MAP_TYPE_ARRAY_OF_MAPS,
	.size_key       = sizeof(__u32),
    .size_value     = sizeof(__u32), // seems that all map_in_map's have this value size
	.inner_id       = 1,
    .pinning        = PIN_GLOBAL_NS,
	.max_elem       = MAX_LABEL_MAPS,
};

static __always_inline int set_label(__u32 label, struct __sk_buff *skb)
{
    __u8 flow_lbl[3];

    skb_load_bytes(skb, FLOWLABEL_OFF, flow_lbl, 3);

    flow_lbl[0] = (0xF0 & flow_lbl[0]) | (0x0F & (label >> 16));
    flow_lbl[1] = (__u8)(label >> 8);
    flow_lbl[2] = (__u8)label;
    skb_store_bytes(skb, FLOWLABEL_OFF, flow_lbl, 3, 0);

    return BPF_OK;
}

static __always_inline int lpm_label(struct bpf_elf_map *label_map, struct __sk_buff *skb)
{
    struct lpm_key_6 key6;
    __u32 *plabel;

    skb_load_bytes(skb, DADDR_OFF, &key6.addr, sizeof(key6.addr));
    key6.prefixlen = 128;
    plabel = map_lookup_elem(label_map, &key6);
    return set_label(plabel ? *plabel : 0, skb);
}

__section("label")
int do_label(struct __sk_buff *skb)
{
    if (skb->protocol != __constant_htons(ETH_P_IPV6))
        return BPF_OK;
    return lpm_label(&flsw_edge_lpm_map, skb);
}

__section("label-fwmk")
int do_labelfwmk(struct __sk_buff *skb)
{
    if (skb->protocol != __constant_htons(ETH_P_IPV6))
        return BPF_OK;
    return set_label(skb->mark, skb);
}

__section("mtlabel")
int do_mtlabel(struct __sk_buff *skb)
{
    __u32 *map_id;
    struct bpf_elf_map *label_map;
    if (skb->protocol != __constant_htons(ETH_P_IPV6))
        return BPF_OK;

    map_id = map_lookup_elem(&flsw_edge_intf_map, &skb->ifindex);
    if (!map_id)
        return BPF_OK;
    label_map = map_lookup_elem(&flsw_edge_lpm_maps, map_id);
    if (!label_map)
        return BPF_OK;
    return lpm_label(label_map, skb);
}

__section("unlabel")
int do_unlabel(struct __sk_buff *skb)
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
