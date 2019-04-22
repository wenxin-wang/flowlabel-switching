#ifndef SUBCOMMANDS_H
#define SUBCOMMANDS_H

#define FORWARD_T_INGRESS "ingress"
#define FORWARD_T_BACKBONE "backbone"
/*
#define FORWARD_T_INGRESS_MT "ingress-mt"
#define FORWARD_T_BACKBONE_MT "backbone-mt"
*/

int ingress_main(int argc, const char *argv[]);
int backbone_main(int argc, const char *argv[]);
/*
int ingress_mt_main(int argc, const char *argv[]);
int backbone_mt_main(int argc, const char *argv[]);
*/

#endif /* SUBCOMMANDS_H */
