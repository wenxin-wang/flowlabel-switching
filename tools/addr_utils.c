#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/types.h>

int parse_address6(const char *str, struct in6_addr *addr)
{
	if (inet_pton(AF_INET6, str, (void *)addr) != 1) {
		fprintf(stderr, "error: invalid ipv6 address %s\n", str);
		return errno ? -errno : -EINVAL;
	}
	return 0;
}

int parse_prefix6(const char *str, struct in6_addr *addr, __u32 *plen)
{
	int len;
	char *slash = strchr(str, '/');
	if (!slash) {
		errno = EINVAL;
		fprintf(stderr,
			"error: prefix %s must be in the format 'prefix/length'\n",
			str);
		return -errno;
	}
	*slash = '\0';
	if (inet_pton(AF_INET6, str, (void *)addr) != 1) {
		fprintf(stderr,
			"error: the address part of the prefix is an invalid ipv6 address %s\n",
			str);
		return errno ? -errno : -EINVAL;
	}
	*slash = '/';
	len = atoi(slash + 1);
	if (len <= 0 || len > 128) {
		errno = EINVAL;
		fprintf(stderr, "error: prefix length %d must be in (0, 128]",
			len);
		return -errno;
	}
	*plen = len;
	return 0;
}
