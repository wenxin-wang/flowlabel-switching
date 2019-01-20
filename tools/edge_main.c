// Borrow a lot from wireguard

#include "subcommands.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EDGE_LABEL_MAP_ENV "EDGE_LABEL_MAP"

const char *EDGE_LABEL_MAP_PATH = "/sys/fs/bpf/ip/globals/flsw_lpm_label_map";

extern const char *PROG_NAME;
extern const char *FORWARD_TYPE;

int edge_show(int argc, const char *argv[]);
int edge_set(int argc, const char *argv[]);
int edge_flush(int argc, const char *argv[]);

static const struct {
	const char *subcommand;
	int (*function)(int, const char**);
	const char *description;
} subcommands[] = {
	{ CMD_SHOW, edge_show, "show information about prefixes and labels" },
	{ CMD_SET, edge_set, "setup prefixes and labels" },
	{ CMD_UNSET, edge_set, "setup prefixes and labels" },
	{ CMD_FLUSH, edge_flush, "cleanup prefixes and labels" },
};

static void edge_usage(FILE *file)
{
	fprintf(file, "Usage: %s <cmd> [<args>]\n\n", PROG_NAME);
	fprintf(file, "Available subcommands:\n");
	for (size_t i = 0; i < sizeof(subcommands) / sizeof(subcommands[0]); ++i)
		fprintf(file, "  %s: %s\n", subcommands[i].subcommand, subcommands[i].description);
    fprintf(file, "Available environment variables:\n");
    fprintf(file, "  " EDGE_LABEL_MAP_ENV ": bpf map for edge labels, defaults to %s\n", EDGE_LABEL_MAP_PATH);
	fprintf(file, "You may pass `--help' to any of these subcommands to view usage.\n");
}

int edge_main(int argc, const char *argv[])
{
	if (argc == 1 && (!strcmp(argv[0], "-h") || !strcmp(argv[0], "--help") || !strcmp(argv[0], "help"))) {
		edge_usage(stdout);
		return 0;
	}

	if (argc < 1) {
		edge_usage(stderr);
		return 1;
	}

	for (size_t i = 0; i < sizeof(subcommands) / sizeof(subcommands[0]); ++i) {
		if (!strcmp(argv[0], subcommands[i].subcommand)) {
            const char* label_map = getenv(EDGE_LABEL_MAP_ENV);
            if (label_map)
                EDGE_LABEL_MAP_PATH = label_map;
			return subcommands[i].function(argc, argv);
        }
	}

	fprintf(stderr, "Invalid subcommand: `%s'\n", argv[1]);
	edge_usage(stderr);
	return 1;
}
