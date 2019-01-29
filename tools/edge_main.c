// Borrow a lot from wireguard

#include "subcommands.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#define BPF_EDGE_MAP_ENV "EDGE_MAP_PATH"
#define BPF_EDGE_MAP_DEF_PATH "ip/globals/flsw_edge_lpm_map"

char BPF_EDGE_MAP_PATH[PATH_MAX];

extern const char *BPF_MNT;
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
    fprintf(file, "  " BPF_EDGE_MAP_ENV
        ": bpf map path (relative or absolute) for edge labels, defaults to "
        BPF_EDGE_MAP_DEF_PATH "\n");
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
            const char* label_map = getenv(BPF_EDGE_MAP_ENV);
            if (!label_map || !strlen(label_map)) {
                snprintf(BPF_EDGE_MAP_PATH, PATH_MAX, "%s/%s", BPF_MNT, BPF_EDGE_MAP_DEF_PATH);
            }
            else if (label_map[0] == '/') {
                strncpy(BPF_EDGE_MAP_PATH, label_map, PATH_MAX);
            }
            else {
                snprintf(BPF_EDGE_MAP_PATH, PATH_MAX, "%s/%s", BPF_MNT, label_map);
            }
			return subcommands[i].function(argc, argv);
        }
	}

	fprintf(stderr, "Invalid subcommand: `%s'\n", argv[1]);
	edge_usage(stderr);
	return 1;
}
