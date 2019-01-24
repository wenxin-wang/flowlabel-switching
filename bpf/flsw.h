#ifndef __FLSW_H__
#define __FLSW_H__

#include "bpf_helpers.h"

#include <linux/ipv6.h>
#include <stddef.h>

#define MAX_LABEL_MAPS 256
#define MAX_LABEL_ENTRIES 256
#define MAX_INTFS 256

#define MAX_LABEL ((1<<20) - 1)

#define FLOWLABEL_OFF offsetof(struct ipv6hdr, flow_lbl)

#endif
