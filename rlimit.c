/* rlimit.c - process limits related stuff
 *
 * Copyright(C) 2002 Salvatore Sanfilippo <antirez@invece.org>
 * All rights reserved.
 * See the LICENSE file for COPYRIGHT and PERMISSION notice */

/* $Id: rlimit.c,v 1.2 2003/09/13 07:10:29 antirez Exp $ */

#include <stdio.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>

int set_core_size(unsigned int size)
{
	struct rlimit rl;

	if (getrlimit(RLIMIT_CORE, &rl) == -1) {
		perror("getrlimit");
		return -1;
	}
	rl.rlim_cur = (size > rl.rlim_max) ? rl.rlim_max : size;
	if (setrlimit(RLIMIT_CORE, &rl) == -1) {
		perror("setrlimit");
		return -1;
	}
	return 0;
}
