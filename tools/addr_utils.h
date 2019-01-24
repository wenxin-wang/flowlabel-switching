#ifndef ADDR_UTILS_H
#define ADDR_UTILS_H

#include <arpa/inet.h>
#include <linux/types.h>

int parse_address6(const char *str, struct in6_addr *addr);
int parse_prefix6(const char *str, struct in6_addr *addr, __u32 *plen);

#endif /* ADDR_UTILS_H */
