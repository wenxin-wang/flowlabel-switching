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


# Examples

See [test/]().

# About `ip netns exec`

The default bpf filesystem, used for pinning bpf programs and maps, is mounted
on `/sys/fs/bpf/` by `iproute2` programs. However, `ip netns exec` happens to
unmount `/sys` before `exec`, so the called program never sees that bpf
filesystem.

And it seems that bpf filesystem cannot be mounted by any command invoked with
`ip netns exec`. I don't know the reason behind.

So before calling `ip netns exec`, mount a bpf file system somewhere other than
`/sys`, e.g. `/run/flsw/bpffs/`, and `ip netns exec` will see that filesystem.

And by setting `TC_BPF_MNT` environment variable to subdirectories of the
previously mounted bpf filesystem, we can have different bpf objects with the
same name for different netns.
