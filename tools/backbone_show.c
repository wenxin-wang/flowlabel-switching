#include "subcommands.h"
#include "../bpf/flsw_backbone_xdp.h"

#include <bcc/libbpf.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <limits.h>

extern const char BPF_BACKBONE_MAP_PATH[PATH_MAX];
extern const char *PROG_NAME;
extern const char *FORWARD_TYPE;

static void backbone_show_usage(FILE *file, const char* cmd) {
	fprintf(file,
    "Usage: %s %s %s\n",
    PROG_NAME, FORWARD_TYPE, cmd);
}

static int print_nexthop(int fd, __u32 in_label) {
    char pref_str[INET6_ADDRSTRLEN];
    struct nexthop_info nhinfo;
    int ret;
    ret = bpf_lookup_elem(fd, &in_label, &nhinfo);
    if (ret < 0) {
        fprintf(stderr, "Error get nexthop for %s: %s\n", pref_str, strerror(errno));
        return ret;
    }
    if (!inet_ntop(AF_INET6, &(nhinfo.nexthop), pref_str, INET6_ADDRSTRLEN)) {
		perror("Error print lpm prefix");
		return -1;
	}
    printf("%d %s %d\n", in_label, pref_str, nhinfo.label);
    return 0;
}

int backbone_show(int argc, const char *argv[]) {
    __u32 cur, next, *pcur, *pnext;
    int fd, ret;

    if (argc == 2 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help") ||
                      !strcmp(argv[1], "help"))) {
		backbone_show_usage(stdout, argv[0]);
		return 0;
	}
	if (argc > 1) {
		backbone_show_usage(stderr, argv[0]);
		return 1;
	}

    fd = bpf_obj_get(BPF_BACKBONE_MAP_PATH);
    if (fd < 0) {
        fprintf(stderr, "Error open map: %s %s\n", BPF_BACKBONE_MAP_PATH, strerror(errno));
        return fd;
    }

    pcur = &cur;
    ret = bpf_get_first_key(fd, pcur, sizeof(*pcur));
    if (ret == -1 && errno == ENOENT)
        return 0;
    else if (ret < 0) {
        fprintf(stderr, "Error get first nexthop: %s\n", strerror(errno));
        return ret;
    }
    ret = print_nexthop(fd, *pcur);
    if (ret < 0) {
        return ret;
    }

    pnext = &next;
    do {
        __u32 *tmp;
        ret = bpf_get_next_key(fd, pcur, pnext);
        if (ret == -1 && errno == ENOENT)
            break;
        else if (ret < 0) {
            fprintf(stderr, "Error get next nexthop: %s\n", strerror(errno));
            return ret;
        }
        ret = print_nexthop(fd, *pnext);
        if (ret < 0) {
            return ret;
        }

        tmp = pcur;
        pcur = pnext;
        pnext = tmp;
    } while (1);

    return 0;
}
