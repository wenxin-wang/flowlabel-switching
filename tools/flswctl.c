#include "forwardtypes.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define BPF_MNT_ENV "TC_BPF_MNT"

const char *BPF_MNT = "/sys/fs/bpf";
const char *PROG_NAME;
const char *FORWARD_TYPE;

static const struct {
	const char *subcommand;
	int (*function)(int, const char **);
	const char *description;
} forwardtypes[] = {
	{ FORWARD_T_INGRESS, ingress_main, "configure flowlabel ingress forwarding" },
	{ FORWARD_T_BACKBONE, backbone_main,
	  "configure flowlabel backbone forwarding" },
	/*
	{ FORWARD_T_INGRESS_MT, ingress_main, "configure flowlabel multi-table ingress forwarding, designed for use with netns" },
	{ FORWARD_T_BACKBONE_MT, backbone_main, "configure flowlabel multi-table backbone forwarding, designed for use with netns" },
    */
};

static void main_usage(FILE *file)
{
	fprintf(file, "Usage: %s <forward type> <cmd> [<args>]\n\n", PROG_NAME);
	fprintf(file, "Available forward types:\n");
	for (size_t i = 0; i < sizeof(forwardtypes) / sizeof(forwardtypes[0]);
	     ++i)
		fprintf(file, "  %s: %s\n", forwardtypes[i].subcommand,
			forwardtypes[i].description);
	fprintf(file, "Available environment variables:\n");
	fprintf(file,
		"  " BPF_MNT_ENV
		": bpf filesystem mount point, defaults to %s\n",
		BPF_MNT);
	fprintf(file,
		"You may pass `--help' to any of these forwardtypes to view usage.\n");
}

int main(int argc, const char *argv[])
{
	const char *bpffs_mnt;

	PROG_NAME = argv[0];
	if (argc == 2 &&
	    (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help") ||
	     !strcmp(argv[1], "help"))) {
		main_usage(stdout);
		return 0;
	}

	if (argc <= 1) {
		main_usage(stderr);
		return 1;
	}

	bpffs_mnt = getenv(BPF_MNT_ENV);
	if (bpffs_mnt)
		BPF_MNT = bpffs_mnt;

	for (size_t i = 0; i < sizeof(forwardtypes) / sizeof(forwardtypes[0]);
	     ++i) {
		if (!strcmp(argv[1], forwardtypes[i].subcommand)) {
			FORWARD_TYPE = argv[1];
			return forwardtypes[i].function(argc - 2, argv + 2);
		}
	}

	fprintf(stderr, "Invalid forward type: `%s'\n", argv[1]);
	main_usage(stderr);
	return 1;
}
