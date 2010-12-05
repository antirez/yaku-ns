/* autoptr.c
 * autoptr code.
 *
 * Copyright (C) 2000,2001,2002 by Salvatore Sanfilippo
 * <antirez@invece.org>
 *
 * This code is under the GPL license
 * See the COPYING file for more information
 */

#include "ens.h"

#include <string.h>
#include <stdlib.h>

/* global */
int opt_autoptr = 0;

/* The function converts the IP address x.y.z.k to
 * the name in-addr.arpa.k.z.y.x, but accepts in
 * input only valid IP addresses.
 * WARNING: The dest buffer MUST be at least 32 bytes long */
int inet_toinaddr(char *addr, char *dest)
{
	char tmp[32]; /* in-addr.arpa.xxx.yyy.zzz.kkk+\0 */
	char *p;
	size_t l = strlen(addr), i;
	
	/* xxx.yyy.zzz.kkk = 15 bytes
	 * x.y.z.k = 7 bytes
	 * accepted chars are only 0123456789. */
	if (l > 15 ||
	    l < 4 ||
	    strspn(addr, "0123456789.") != l ||
	    strstr(addr, "..") ||
	    addr[0] == '.'  ||
	    addr[l-1] == '.')
		return CERROR_BADIP;

	dest[0] = '\0';
	memcpy(tmp, addr, l+1);
	for(i = 0; i < 3; i++) {
		if((p = strrchr(tmp, '.')) == NULL)
			return CERROR_BADIP;
		*p = '\0';
		if (atoi(p+1) > 255 || atoi(p+1) < 0)
			return CERROR_BADIP;
		strlcat(dest, p+1, 32);
		strlcat(dest, ".", 32);
	}
	strlcat(dest, tmp, 32);
	strlcat(dest, ".in-addr.arpa", 32);
	return 0;
}

#ifdef TESTMAIN
#include <stdio.h>
int main(int argc, char **argv)
{
	char buffer[32];

	if (argc != 2) {
		printf("usage: program <address>\n");
		exit(1);
	}

	if (inet_toinaddr(argv[1], buffer) != 0) {
		printf("Forname error\n");
	} else {
		printf("%s\n", buffer);
	}
	return 0;
}
#endif
