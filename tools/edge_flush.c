#include "subcommands.h"
#include "bpf_label.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <arpa/inet.h>

extern const char *PROG_NAME;
extern const char *FORWARD_TYPE;
extern const char *EDGE_LABEL_MAP_PATH;

static void edge_flush_usage(FILE *file, const char* cmd) {
	fprintf(file,
    "Usage: %s %s %s\n",
    PROG_NAME, FORWARD_TYPE, cmd);
}

int edge_flush(int argc, const char *argv[]) {
    struct lpm_key_6 cur, next, *pcur, *pnext;
    int fd, ret;

    if (argc == 2 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help") ||
                      !strcmp(argv[1], "help"))) {
		edge_flush_usage(stdout, argv[0]);
		return 0;
	}
	if (argc > 1) {
		edge_flush_usage(stderr, argv[0]);
		return 1;
	}

    fd = open_label_map(EDGE_LABEL_MAP_PATH);
    if (fd < 0) {
        fprintf(stderr, "Error open map: %s %s\n", EDGE_LABEL_MAP_PATH, strerror(errno));
        return fd;
    }

    pcur = &cur;
    ret = first_lpm_label(fd, pcur);
    if (ret < 0) {
        fprintf(stderr, "Error get first label: %s\n", strerror(errno));
        return ret;
    }

    pnext = &next;
    do {
        struct lpm_key_6 *tmp;
        int no_next;
        ret = next_lpm_label(fd, pcur, pnext);
        no_next = (ret == -1 && errno == ENOENT);
        if (ret < 0 && !no_next) {
            fprintf(stderr, "Error get next label: %s\n", strerror(errno));
            return ret;
        }
        ret = del_lpm_label(fd, pcur);
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
