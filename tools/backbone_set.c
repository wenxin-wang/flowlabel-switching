#include "subcommands.h"
#include "addr_utils.h"
#include "../bpf/flsw_backbone_xdp.h"

#include <bcc/libbpf.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <limits.h>

extern const char BPF_BACKBONE_MAP_PATH[PATH_MAX];
extern const char *PROG_NAME;
extern const char *FORWARD_TYPE;

static int is_unset;

static void backbone_set_usage(FILE *file, const char* cmd) {
	fprintf(file,
    "Usage: %s %s %s <label> [<ipv6 nexthop> <label>]\n"
    "Note:\nWhen unsetting label for a <prefix>, specify only the <prefix>.\n",
    PROG_NAME, FORWARD_TYPE, cmd);
}

int backbone_set(int argc, const char *argv[]) {
    struct nexthop_info nhinfo;
    int fd, in_label, ret;

    if (argc == 2 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help") ||
                      !strcmp(argv[1], "help"))) {
		backbone_set_usage(stdout, argv[0]);
		return 0;
	}
	is_unset = !strcmp(argv[0], CMD_UNSET);
	if (is_unset ? argc < 2 : argc < 4) {
		backbone_set_usage(stderr, argv[0]);
		return -1;
	}

    in_label = atoi(argv[1]);
    if (in_label <= 0 || in_label > MAX_LABEL) {
		errno = EINVAL;
        fprintf(stderr, "Invalid inbound label %d\n", in_label);
		return -1;
	}

    fd = bpf_obj_get(BPF_BACKBONE_MAP_PATH);
        if (fd < 0) {
            fprintf(stderr, "Error open map: %s %s\n", BPF_BACKBONE_MAP_PATH, strerror(errno));
        return fd;
    }

    if (is_unset) {
        ret = bpf_delete_elem(fd, &in_label);
        if (ret < 0) {
            printf("Error unset %s: %s\n", argv[1], strerror(errno));
        }
        return ret;
    }

    ret = parse_address6(argv[2], &nhinfo.nexthop);
    if (ret)
        return ret;

    nhinfo.label = atoi(argv[3]);
    if (nhinfo.label <= 0 || nhinfo.label > MAX_LABEL) {
		errno = EINVAL;
        fprintf(stderr, "Invalid outbound label %d\n", nhinfo.label);
		return -1;
	}

    ret = bpf_update_elem(fd, &in_label, &nhinfo, BPF_ANY);
    if (ret < 0) {
        printf("Error set %s %s: %s\n", argv[1], argv[2], strerror(errno));
    }
    return ret;
}
