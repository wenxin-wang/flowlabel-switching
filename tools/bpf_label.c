#include "bpf_label.h"

#include <bcc/libbpf.h>

int open_label_map(const char* path) {
    return bpf_obj_get(path);
}

int add_lpm_label(int fd, struct lpm_key_6 *prefix, __u32 label) {
    return bpf_update_elem(fd, prefix, &label, BPF_ANY);
}

int del_lpm_label(int fd, struct lpm_key_6 *prefix) {
    return bpf_delete_elem(fd, prefix);
}

int get_lpm_label(int fd, struct lpm_key_6 *prefix, __u32 *label) {
    return bpf_lookup_elem(fd, prefix, label);
}

int first_lpm_label(int fd, struct lpm_key_6 *prefix) {
    return bpf_get_first_key(fd, prefix, sizeof(*prefix));
}

int next_lpm_label(int fd, struct lpm_key_6 *cur, struct lpm_key_6 *next) {
    return bpf_get_next_key(fd, cur, next);
}
