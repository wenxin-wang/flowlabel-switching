#include "iproute2_bpf_helpers.h"

#include <stddef.h>
#include <linux/ipv6.h>
#include <linux/if_ether.h>

#define MAX_LABEL_ENTRIES 256

// Flowlabel is 12-31 bit of an ipv6 header (20 bits),
// but lwt xmit bpf can only load and store bytes.
// So load 3 bytes, change the flowlabel part,
// and store them back.
// Kernel does the same trick with struct ipv6hdr's flow_lbl field

#define FLOWLABEL_OFF offsetof(struct ipv6hdr, flow_lbl)
#define DADDR_OFF offsetof(struct ipv6hdr, daddr)

struct lpm_key_6 {
	__u32	prefixlen;     // Always set to 128 for looking up
    struct in6_addr addr;
};

struct bpf_elf_map flsw_lpm_label_map __section("maps") = {
    .type           = BPF_MAP_TYPE_LPM_TRIE,
    .size_key       = sizeof(struct lpm_key_6),
    .size_value     = sizeof(__u32),
    .pinning        = PIN_GLOBAL_NS,
    .max_elem       = MAX_LABEL_ENTRIES,
	.flags          = BPF_F_NO_PREALLOC,
};

__section("label")
int do_label(struct __sk_buff *skb)
{
    struct lpm_key_6 key6;
    __u32 label = 0; // only use the lower 20 bits
    __u32 *plabel;
    __u8 flow_lbl[3];
    if (skb->protocol != __constant_htons(ETH_P_IPV6))
        return BPF_OK;

    skb_load_bytes(skb, FLOWLABEL_OFF, flow_lbl, 3);
    skb_load_bytes(skb, DADDR_OFF, &key6.addr, sizeof(key6.addr));
    key6.prefixlen = 128;
    plabel = map_lookup_elem(&flsw_lpm_label_map, &key6);
    if (plabel)
        label = *plabel;

    flow_lbl[0] = (0xF0 & flow_lbl[0]) | (0x0F & (label >> 16));
    flow_lbl[1] = (__u8)(label >> 8);
    flow_lbl[2] = (__u8)label;
    skb_store_bytes(skb, FLOWLABEL_OFF, flow_lbl, 3, 0);

    return BPF_OK;
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
