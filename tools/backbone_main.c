// Borrow a lot from wireguard

#include "subcommands.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#define BPF_BACKBONE_MAP_ENV "BACKBONE_MAP_PATH"
#define BPF_BACKBONE_MAP_DEF_PATH "xdp/globals/flsw_backbone_nexthop_map"

char BPF_BACKBONE_MAP_PATH[PATH_MAX];

extern const char *BPF_MNT;
extern const char *PROG_NAME;
extern const char *FORWARD_TYPE;

int backbone_show(int argc, const char *argv[]);
int backbone_set(int argc, const char *argv[]);
int backbone_flush(int argc, const char *argv[]);

static const struct {
	const char *subcommand;
	int (*function)(int, const char**);
	const char *description;
} subcommands[] = {
	{ CMD_SHOW, backbone_show, "show information about labels and nexthops" },
	{ CMD_SET, backbone_set, "setup labels and nexthops" },
	{ CMD_UNSET, backbone_set, "setup labels and nexthops" },
	{ CMD_FLUSH, backbone_flush, "cleanup labels and nexthops" },
};

static void backbone_usage(FILE *file)
{
	fprintf(file, "Usage: %s <cmd> [<args>]\n\n", PROG_NAME);
	fprintf(file, "Available subcommands:\n");
	for (size_t i = 0; i < sizeof(subcommands) / sizeof(subcommands[0]); ++i)
		fprintf(file, "  %s: %s\n", subcommands[i].subcommand, subcommands[i].description);
    fprintf(file, "Available environment variables:\n");
    fprintf(file, "  " BPF_BACKBONE_MAP_ENV
    ": bpf map path (relative or absolute) for backbond nexthops, defaults to "
    BPF_BACKBONE_MAP_DEF_PATH "\n");
	fprintf(file, "You may pass `--help' to any of these subcommands to view usage.\n");
}

int backbone_main(int argc, const char *argv[])
{
	if (argc == 1 && (!strcmp(argv[0], "-h") || !strcmp(argv[0], "--help") || !strcmp(argv[0], "help"))) {
		backbone_usage(stdout);
		return 0;
	}

	if (argc < 1) {
		backbone_usage(stderr);
		return 1;
	}

	for (size_t i = 0; i < sizeof(subcommands) / sizeof(subcommands[0]); ++i) {
		if (!strcmp(argv[0], subcommands[i].subcommand)) {
            const char* nexthop_map = getenv(BPF_BACKBONE_MAP_ENV);
            if (!nexthop_map || !strlen(nexthop_map)) {
                snprintf(BPF_BACKBONE_MAP_PATH, PATH_MAX, "%s/%s", BPF_MNT, BPF_BACKBONE_MAP_DEF_PATH);
            }
            else if (nexthop_map[0] == '/') {
                strncpy(BPF_BACKBONE_MAP_PATH, nexthop_map, PATH_MAX);
            }
            else {
                snprintf(BPF_BACKBONE_MAP_PATH, PATH_MAX, "%s/%s", BPF_MNT, nexthop_map);
            }
			return subcommands[i].function(argc, argv);
        }
	}

	fprintf(stderr, "Invalid subcommand: `%s'\n", argv[1]);
	backbone_usage(stderr);
	return 1;
}
