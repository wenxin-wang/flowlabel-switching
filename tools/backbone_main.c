// Borrow a lot from wireguard

#include "subcommands.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BACKBONE_NEXTHOP_MAP_ENV "BACKBONE_NEXTHOP_MAP"

const char *BACKBONE_NEXTHOP_MAP_PATH = "/sys/fs/bpf/xdp/globals/flsw_backbone_nexthop_map";

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
    fprintf(file, "  " BACKBONE_NEXTHOP_MAP_ENV ": bpf map for backbone nexthops, defaults to %s\n", BACKBONE_NEXTHOP_MAP_PATH);
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
            const char* nexthop_map = getenv(BACKBONE_NEXTHOP_MAP_ENV);
            if (nexthop_map)
                BACKBONE_NEXTHOP_MAP_PATH = nexthop_map;
			return subcommands[i].function(argc, argv);
        }
	}

	fprintf(stderr, "Invalid subcommand: `%s'\n", argv[1]);
	backbone_usage(stderr);
	return 1;
}
