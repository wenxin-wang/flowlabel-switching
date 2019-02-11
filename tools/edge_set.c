#include "subcommands.h"
#include "addr_utils.h"
#include "../bpf/flsw_edge_lwt.h"

#include <bcc/libbpf.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <limits.h>

extern const char BPF_EDGE_MAP_PATH[PATH_MAX];
extern const char *PROG_NAME;
extern const char *FORWARD_TYPE;

static int is_unset;

static void edge_set_usage(FILE *file, const char *cmd)
{
	fprintf(file,
		"Usage: %s %s %s <prefix> [<label>]\n"
		"Note:\nWhen unsetting label for a <prefix>, specify only the <prefix>.\n",
		PROG_NAME, FORWARD_TYPE, cmd);
}

int edge_set(int argc, const char *argv[])
{
	struct lpm_key_6 prefix;
	int fd, label, ret;

	if (argc == 2 &&
	    (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help") ||
	     !strcmp(argv[1], "help"))) {
		edge_set_usage(stdout, argv[0]);
		return 0;
	}
	is_unset = !strcmp(argv[0], CMD_UNSET);
	if (is_unset ? argc < 2 : argc < 3) {
		edge_set_usage(stderr, argv[0]);
		return -1;
	}

	ret = parse_prefix6(argv[1], &prefix.addr, &prefix.prefixlen);
	if (ret) {
		fprintf(stderr, "error parse prefix %s", argv[1]);
		return ret;
	}

	fd = bpf_obj_get(BPF_EDGE_MAP_PATH);
	if (fd < 0) {
		fprintf(stderr, "Error open map %s: %s\n", BPF_EDGE_MAP_PATH,
			strerror(errno));
		return fd;
	}

	if (is_unset) {
		ret = bpf_delete_elem(fd, &prefix);
		if (ret < 0) {
			printf("Error unset %s: %s\n", argv[1],
			       strerror(errno));
		}
		return ret;
	}

	label = atoi(argv[2]);
	if (label <= 0 || label > MAX_LABEL) {
		errno = EINVAL;
		fprintf(stderr, "Invalid label %d\n", label);
		return -1;
	}

	ret = bpf_update_elem(fd, &prefix, &label, BPF_ANY);
	if (ret < 0) {
		printf("Error set %s %s: %s\n", argv[1], argv[2],
		       strerror(errno));
	}
	return ret;
}
