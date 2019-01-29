#include "subcommands.h"
#include "../bpf/flsw_edge_lwt.h"

#include <bcc/libbpf.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <limits.h>

extern const char BPF_EDGE_MAP_PATH[PATH_MAX];
extern const char *PROG_NAME;
extern const char *FORWARD_TYPE;

static void edge_show_usage(FILE *file, const char* cmd) {
	fprintf(file,
    "Usage: %s %s %s\n",
    PROG_NAME, FORWARD_TYPE, cmd);
}

static int print_prefix_label(int fd, struct lpm_key_6 *prefix) {
    char pref_str[INET6_ADDRSTRLEN];
    __u32 label;
    int ret;
    if (!inet_ntop(AF_INET6, &(prefix->addr), pref_str, INET6_ADDRSTRLEN)) {
		perror("Error print lpm prefix");
		return -1;
	}
    ret = bpf_lookup_elem(fd, prefix, &label);
    if (ret < 0) {
        fprintf(stderr, "Error get label for %s: %s\n", pref_str, strerror(errno));
        return ret;
    }
    printf("%s/%d %d\n", pref_str, prefix->prefixlen, label);
    return 0;
}

int edge_show(int argc, const char *argv[]) {
    struct lpm_key_6 cur, next, *pcur, *pnext;
    int fd, ret;

    if (argc == 2 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help") ||
                      !strcmp(argv[1], "help"))) {
		edge_show_usage(stdout, argv[0]);
		return 0;
	}
	if (argc > 1) {
		edge_show_usage(stderr, argv[0]);
		return 1;
	}

    fd = bpf_obj_get(BPF_EDGE_MAP_PATH);
    if (fd < 0) {
        fprintf(stderr, "Error open map: %s %s\n", BPF_EDGE_MAP_PATH, strerror(errno));
        return fd;
    }

    pcur = &cur;
    ret = bpf_get_first_key(fd, pcur, sizeof(*pcur));
    if (ret == -1 && errno == ENOENT)
        return 0;
    else if (ret < 0) {
        fprintf(stderr, "Error get first label: %s\n", strerror(errno));
        return ret;
    }
    ret = print_prefix_label(fd, pcur);
    if (ret < 0) {
        return ret;
    }

    pnext = &next;
    do {
        struct lpm_key_6 *tmp;
        ret = bpf_get_next_key(fd, pcur, pnext);
        if (ret == -1 && errno == ENOENT)
            break;
        else if (ret < 0) {
            fprintf(stderr, "Error get next label: %s\n", strerror(errno));
            return ret;
        }
        ret = print_prefix_label(fd, pnext);
        if (ret < 0) {
            return ret;
        }

        tmp = pcur;
        pcur = pnext;
        pnext = tmp;
    } while (1);

    return 0;
}
