# Edge

label: lwt xmit
switching: like backbone
unlabel: lwt xmit

# Backbone

switching: xdp/tc bpf
fallback: unlabel + routing: switching fallback to this when seeing unknown label (sets label to 0 before routing) or label 0

# label

lwt xmit bpf cannot have arguments

1. lpm match for a label value
2. if not match, do nothing
3. if match, change flowlabel


# Test Setup
## Edge

```bash
sudo ip -6 r add fdde::/64 dev tun0 encap bpf xmit obj bpf/flsw_edge_lwt.o section label verbose
sudo ip l set dev tun0 xdp obj bpf/flsw_backbone_xdp.o section fwd verbose

sudo ip -6 r del fdde::/64
sudo ip l set dev tun0 xdp off
```
