# Edge

1. labeling: lwt xmit
2. switching: like backbone
3. unlabeling: lwt xmit

## Labeling

lwt xmit bpf cannot have arguments

1. lpm match for a label value
2. if not match, unset flowlabel
3. if match, change flowlabel
4. continue routing

## Unlabeling

Just set flowlabel to 0

# Backbone

xdp/tc bpf

## Fallback

unlabel + routing: switching fallback to this when seeing 0-label or unknown
label (sets label to 0 before routing)

# Build

## Prerequisites

1. linux-kernel >= 4.18 (for `fib_lookup`): See [BPF Features by Linux Kernel
   Version](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md)
2. bcc: for libbpf

## Build & Install

```bash
cd flowlabel-switching/
make
```

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
