#ifndef SUBCOMMANDS_H
#define SUBCOMMANDS_H

#define FORWARD_T_EDGE "edge"
#define FORWARD_T_BACKBONE "backbone"
/*
#define FORWARD_T_EDGE_MT "edge-mt"
#define FORWARD_T_BACKBONE_MT "backbone-mt"
*/

int edge_main(int argc, const char *argv[]);
int backbone_main(int argc, const char *argv[]);
/*
int edge_mt_main(int argc, const char *argv[]);
int backbone_mt_main(int argc, const char *argv[]);
*/

#endif /* SUBCOMMANDS_H */
