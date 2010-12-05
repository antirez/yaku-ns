/* unix.c
 *
 * Copyright (C) 2000,2001,2002 by Salvatore Sanfilippo
 * <antirez@invece.org>
 *
 * This code is under the GPL license version 2
 * See the COPYING file for more information
 */

/* ens.h must be included before all other includes */
#include "ens.h"

#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/* from Richard Stevens's UNP */
void daemon_init(void)
{
	int c;

	c = fork();
	if (c == -1) {
		perror("[daemon_init] fork");
		exit(1);
	}
	if (c) exit(0);	/* parent termination */

	setsid(); /* new session */
	Signal(SIGHUP, SIG_IGN);

	c = fork();
	if (c == -1) {
		perror("[daemon_init] fork");
		exit(1);
	}
	if (c) exit(0);	/* first child termination */

	for (c = 0; c < 64; c++)
		close(c);
	if (open("/dev/null", O_RDWR) != 0 ||
	    open("/dev/null", O_RDWR) != 1 ||
	    open("/dev/null", O_RDWR) != 2) {
		perror("[daemon_init] opening /dev/null");
		exit(1);
	}
}
