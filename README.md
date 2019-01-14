# Edge

label: lwt xmit
switching: like backbone
unlabel: just let switching fallback to routing

# Backbone

switching: xdp/tc bpf

# Fallback

unlabel + routing: switching fallback to this when seeing unknown label (sets label to 0 before routing) or label 0

# label

lwt xmit bpf cannot have arguments

1. lpm match for a label value
2. if not match, do nothing
3. if match, change flowlabel


# Test Setup
## Edge

```bash
sudo ip -6 r add fdde::/64 dev tun0 encap bpf xmit obj bpf/flsw_lwt.o section label

sudo ip -6 r del fdde::/64
```
