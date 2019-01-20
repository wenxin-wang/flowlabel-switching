#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/types.h>

int parse_prefix6(const char *str, struct in6_addr *addr, __u32 *plen) {
	int len;
	char *slash = strchr(str, '/');
	if (!slash) {
		errno = EINVAL;
		perror("error parse rule, prefix must be in the format 'prefix/length'");
		return -errno;
	}
	*slash = '\0';
	if (inet_pton(AF_INET6, str, (void *)addr) != 1) {
		perror("error parse rule, the prefix part is an invalid ipv6 address");
		return errno ? -errno : -EINVAL;
	}
	*slash = '/';
	len = atoi(slash + 1);
	if (len <= 0 || len > 96) {
		errno = EINVAL;
		perror("error parse rule, the length of the prefix must be in (0, 96]");
		return -errno;
	}
	*plen = len;
	return 0;
}
