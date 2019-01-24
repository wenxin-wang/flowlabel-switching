#ifndef BPF_LABEL_H
#define BPF_LABEL_H

#include "../bpf/flsw_edge_lwt.h"

int open_label_map(const char* path);
int add_lpm_label(int fd, struct lpm_key_6 *prefix, __u32 label);
int del_lpm_label(int fd, struct lpm_key_6 *prefix);
int get_lpm_label(int fd, struct lpm_key_6 *prefix, __u32 *label);
int first_lpm_label(int fd, struct lpm_key_6 *prefix);
int next_lpm_label(int fd, struct lpm_key_6 *cur, struct lpm_key_6 *next);

#endif /* BPF_LABELS_H */
