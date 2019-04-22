// Borrow a lot from wireguard

#include "subcommands.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#define BPF_INGRESS_MAP_ENV "INGRESS_MAP_PATH"
#define BPF_INGRESS_MAP_DEF_PATH "ip/globals/flsw_ingress_lpm_map"

char BPF_INGRESS_MAP_PATH[PATH_MAX];

extern const char *BPF_MNT;
extern const char *PROG_NAME;
extern const char *FORWARD_TYPE;

int ingress_show(int argc, const char *argv[]);
int ingress_set(int argc, const char *argv[]);
int ingress_flush(int argc, const char *argv[]);

static const struct {
	const char *subcommand;
	int (*function)(int, const char **);
	const char *description;
} subcommands[] = {
	{ CMD_SHOW, ingress_show, "show information about prefixes and labels" },
	{ CMD_SET, ingress_set, "setup prefixes and labels" },
	{ CMD_UNSET, ingress_set, "setup prefixes and labels" },
	{ CMD_FLUSH, ingress_flush, "cleanup prefixes and labels" },
};

static void ingress_usage(FILE *file)
{
	fprintf(file, "Usage: %s <cmd> [<args>]\n\n", PROG_NAME);
	fprintf(file, "Available subcommands:\n");
	for (size_t i = 0; i < sizeof(subcommands) / sizeof(subcommands[0]);
	     ++i)
		fprintf(file, "  %s: %s\n", subcommands[i].subcommand,
			subcommands[i].description);
	fprintf(file, "Available environment variables:\n");
	fprintf(file,
		"  " BPF_INGRESS_MAP_ENV
		": bpf map path (relative or absolute) for ingress labels, defaults to " BPF_INGRESS_MAP_DEF_PATH
		"\n");
	fprintf(file,
		"You may pass `--help' to any of these subcommands to view usage.\n");
}

int ingress_main(int argc, const char *argv[])
{
	if (argc == 1 &&
	    (!strcmp(argv[0], "-h") || !strcmp(argv[0], "--help") ||
	     !strcmp(argv[0], "help"))) {
		ingress_usage(stdout);
		return 0;
	}

	if (argc < 1) {
		ingress_usage(stderr);
		return 1;
	}

	for (size_t i = 0; i < sizeof(subcommands) / sizeof(subcommands[0]);
	     ++i) {
		if (!strcmp(argv[0], subcommands[i].subcommand)) {
			const char *label_map = getenv(BPF_INGRESS_MAP_ENV);
			if (!label_map || !strlen(label_map)) {
				snprintf(BPF_INGRESS_MAP_PATH, PATH_MAX, "%s/%s",
					 BPF_MNT, BPF_INGRESS_MAP_DEF_PATH);
			} else if (label_map[0] == '/') {
				strncpy(BPF_INGRESS_MAP_PATH, label_map, PATH_MAX);
			} else {
				snprintf(BPF_INGRESS_MAP_PATH, PATH_MAX, "%s/%s",
					 BPF_MNT, label_map);
			}
			return subcommands[i].function(argc, argv);
		}
	}

	fprintf(stderr, "Invalid subcommand: `%s'\n", argv[1]);
	ingress_usage(stderr);
	return 1;
}
