/* log.c
 * Functions to perform logging
 *
 * Copyright (C) 2000,2001,2002 by Salvatore Sanfilippo
 * <antirez@invece.org>
 *
 * This code is under the GPL license
 * See the COPYING file for more information
 */

/* ens.h must be included before all other includes */
#include "ens.h"

#include <stdio.h>
#include <stdarg.h>
#include <time.h>

/* global vars */
FILE *logfp = NULL;
int opt_logtime = 1;
int opt_verbose = 0;

/* exported functions */
int log(int level, char *fmt, ...);
int log_flush(void);
void open_logfile(char *filename);

/* Just log the printf-like message */
int log(int level, char *fmt, ...)
{
	time_t t;
	struct tm *tmtime;
	char timestring[64];
	int ret = 0;
	va_list ap;

	/* Return ASAP if we can't log the message */
	if (opt_verbose < level || logfp == NULL)
		return 0;

	t = time(NULL);
	tmtime = gmtime(&t);

	va_start(ap, fmt);
	/* Log the timestamp */
	if (opt_logtime &&
            strftime(timestring, 64, "%Y/%m/%d %T] ", tmtime) != 0)
		fprintf(logfp, "%s", timestring);
	/* Log the message */
	DEBUG(if(level == VERB_DEBUG) fprintf(logfp, "[DEBUG] ");)
	ret = vfprintf(logfp, fmt, ap);
	va_end(ap);
	return ret;
}

/* Flush the log buffer */
int log_flush(void)
{
	return fflush(logfp);
}

/* Open the log file */
void open_logfile(char *filename)
{       
	FILE *fp;
	fp = fopen(filename, "a");
	if (!fp) {
		perror("[open_logfile] Opening the log file: fopen");
		return;
	}
	logfp = fp;
}
