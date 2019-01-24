#include "subcommands.h"
#include "../bpf/flsw_backbone_xdp.h"

#include <bcc/libbpf.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <arpa/inet.h>

extern const char *PROG_NAME;
extern const char *FORWARD_TYPE;
extern const char *BACKBONE_NEXTHOP_MAP_PATH;

static void backbone_flush_usage(FILE *file, const char* cmd) {
	fprintf(file,
    "Usage: %s %s %s\n",
    PROG_NAME, FORWARD_TYPE, cmd);
}

int backbone_flush(int argc, const char *argv[]) {
    __u32 cur, next, *pcur, *pnext;
    int fd, ret;

    if (argc == 2 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help") ||
                      !strcmp(argv[1], "help"))) {
		backbone_flush_usage(stdout, argv[0]);
		return 0;
	}
	if (argc > 1) {
		backbone_flush_usage(stderr, argv[0]);
		return 1;
	}

    fd = bpf_obj_get(BACKBONE_NEXTHOP_MAP_PATH);
    if (fd < 0) {
        fprintf(stderr, "Error open map: %s %s\n", BACKBONE_NEXTHOP_MAP_PATH, strerror(errno));
        return fd;
    }

    pcur = &cur;
    ret = bpf_get_first_key(fd, pcur, sizeof(*pcur));
    if (ret < 0) {
        fprintf(stderr, "Error get first label: %s\n", strerror(errno));
        return ret;
    }

    pnext = &next;
    do {
        __u32 *tmp;
        int no_next;
        ret = bpf_get_next_key(fd, pcur, pnext);
        no_next = (ret == -1 && errno == ENOENT);
        if (ret < 0 && !no_next) {
            fprintf(stderr, "Error get next label: %s\n", strerror(errno));
            return ret;
        }
        ret = bpf_delete_elem(fd, pcur);
        if (ret < 0) {
            fprintf(stderr, "Error unset label: %s\n", strerror(errno));
            return ret;
        }

        if (no_next) {
            break;
        }
        tmp = pcur;
        pcur = pnext;
        pnext = tmp;
    } while (1);

    return 0;
}
