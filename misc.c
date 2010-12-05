/* misc.c
 * miscellaneous code
 *
 * Copyright (C) 2000,2001,2002 by Salvatore Sanfilippo
 * <antirez@invece.org>
 *
 * This code is under the GPL license
 * See the COPYING file for more information
 */

/* ens.h must be included before all other includes */
#include "ens.h"
#include "aht.h"

#ifdef __unix__
#include <sys/time.h>
#include <unistd.h>
#endif /* __unix__ */
#include <time.h>
#include <string.h>
#include <stdlib.h>

/* not exported functions */

/* exported functions */
u_int32_t get_rand32(void);
time_t get_sec(void);
char *qtype_to_str(unsigned short qtype);
char *qclass_to_str(unsigned short qclass);
int line_splitter(char *buffer, char *commandargs[], int argmax);
void dump_state(void);
u_int16_t get_rand_id(void);

/* --------------------------------------------------------------------------- */

time_t get_sec(void)
{
	return time(NULL);
}

char *qtype_to_str(unsigned short qtype)
{
	int i;
	static struct _QTYPE {
		unsigned short code;
		char *str;
	} qtype_str[] = {
		{ 1, "A" },
		{ 2, "NS" },
		{ 3, "MD" },
		{ 4, "MF" },
		{ 5, "CNAME" },
		{ 6, "SOA" },
		{ 7, "MB" },
		{ 8, "MG" },
		{ 9, "MR" },
		{ 10, "NULL" },
		{ 11, "WKS" },
		{ 12, "PTR" },
		{ 13, "HINFO" },
		{ 14, "MINFO" },
		{ 15, "MX" },
		{ 16, "TXT" },
		{ 17, "RP" },
		{ 18, "AFSDB" },
		{ 19, "X25" },
		{ 20, "ISDN" },
		{ 21, "RT" },
		{ 22, "NSAP" },
		{ 23, "NSAP_PTR"},
		{ 24, "SIG"},
		{ 25, "KEY"},
		{ 26, "PX"},
		{ 27, "GPOS"},
		{ 28, "AAAA"},
		{ 29, "LOC"},
		{ 30, "NXT"},
		{ 31, "EID"},
		{ 32, "NIMLOC"},
		{ 33, "SRV"},
		{ 34, "ATMA"},
		{ 35, "NAPTR"},
		{ 36, "KX"},
		{ 37, "CERT"},
		{ 38, "A6"},
		{ 39, "DNAME"},
		{ 40, "SINK"},
		{ 41, "OPT"},
/* non standard */
		{ 100, "UINFO"},
		{ 101, "UID"},
		{ 102, "GID"},
		{ 103, "UNSPEC"},
/* Query type values which do not appear in resource records */
		{ 249, "TKEY"},
		{ 250, "TSIG"},
		{ 251, "IXFR"},
		{ 252, "AXFR" },
		{ 253, "MAILB" },
		{ 254, "MAILA" },
		{ 255, "*" },
		{ 256, "bind-ZXFR"},
		{ 0, NULL} /* NUL TERM */
	};
	for (i = 0; qtype_str[i].code; i++) {
		if (qtype_str[i].code == qtype)
			return qtype_str[i].str;
	}
	return "UNKNOWN";
}

char *qclass_to_str(unsigned short qclass)
{
	int i;
	static struct _QCLASS {
		unsigned short code;
		char *str;
	} qclass_str[] = {
		{ 1, "IN" },
		{ 2, "CS" },
		{ 3, "CH" },
		{ 4, "HS" },
		{ 255, "*" },
		{ 0, NULL} /* NUL TERM */
	};

	for (i = 0; qclass_str[i].code; i++) {
		if (qclass_str[i].code == qclass)
			return qclass_str[i].str;
	}
	return "UNKNOWN";
}

#define skip_spacetab() while(*p == ' ' || *p == '\t') p++
int line_splitter(char *buffer, char *commandargs[], int argmax)
{
	char *p = buffer, *d;
	char tmp[1024];
	int size;
	int argindex = 0;

	/* if buffer is a NULL pointer free commandargs memory */
	if (buffer == NULL) {
		for (; commandargs[argindex] != NULL; argindex++)
			free(commandargs[argindex]);
		return argindex;
	}

	/* otherwise parse the command line */
	while(*p != '\0') {
		size = 0;
		d = tmp;
		skip_spacetab();

		while(*p != ' ' && *p != '\t') {
			if (*p == '\0' || *p == '\n' ||
			    *p == '\r' || size >= 1023)
				break;
			*d++ = *p++;
			size++;
		}

		if (size != 0) {
			commandargs[argindex] = malloc(size+1);
			if (commandargs[argindex] == NULL) {
				perror("[line_splitter] malloc");
				exit(1);
			}
			strlcpy(commandargs[argindex], tmp, size+1);
		} else {
			break;
		}

		argindex++;
		if (argindex >= argmax)
			break;
	}
	commandargs[argindex] = NULL;
	return argindex;
}

void dump_state(void)
{
	ylog(VERB_FORCE,
	"dump_state() requested, dump follows\n"
	"\n-- GENERAL\n"
	"s = %d\n"
	"configfile = %s\n"
	"opt_udp_port = %d\n"
	"local_size = %u\n"
	"local_used = %u\n"
	"\n-- FORWARDING\n"
	"opt_forward = %d\n"
	"dns_forward_port = %d\n"
	"forward_server = %s\n"
	"forward_count = %d\n"
	"forward_size = %u\n"
	"forward_used = %u\n"
	"\n-- CACHE\n"
	"opt_cache = %d\n"
	"cache_count = %d\n"
	"cache_table_size = %u\n"
	"cache_table_used = %u\n"
	"\n-- STATS\n"
	"statistic_received_packet = %d\n"
	"statistic_invalid_packet = %d\n"
	"statistic_query_count = %d\n"
	"statistic_iquery_count = %d\n"
	"statistic_response_count = %d\n"
	"\n",	s, configfile, opt_udp_port, local_table.size, local_table.used,
		opt_forward, dns_forward_port, inet_ntoa(forward_server[0]),
		forward_count, forward_table.size, forward_table.used,
		opt_cache, cache_count, cache_table.size, cache_table.used,
		statistic_received_packet, statistic_invalid_packet,
		statistic_query_count, statistic_iquery_count,
		statistic_response_count);
	fflush(logfp);
}

/* Don't expect maximun security here, anyway the id is 16 bit large */
u_int16_t get_rand_id(void)
{
	u_int32_t id;
	static u_int16_t inc = 0;
#ifdef __unix__
	struct timeval tmptv;

	gettimeofday(&tmptv, NULL);
	id = tmptv.tv_usec ^ tmptv.tv_sec ^ getpid() ^ inc++;
#else /* not __unix__ */
	id = rand() ^ time(NULL) ^ clock() ^ inc++;
#endif /* not __unix__ */
	return (u_int16_t) (id & 0xffff);
}

/* WARNING: THIS MAY WORK ONLY WITH GNU MALLOC
   but this stuff is used only to trace memory leaks
   and isn't part of a normal ENS binary */
#ifdef TRACE_LEAKS
#undef malloc
#undef realloc
#undef free
void tl_current(int x, int y);

void *tl_malloc(char *file, int line, size_t size)
{
	void *ptr = malloc(size);
	int *l = (int*) ptr;
	printf("%s %d: malloc(%d) = %p, ", file, line, size, ptr);
	if (size == 0) {
		printf("malloc zero\n");
		exit(1);
	}
	printf("allocated %d bytes\n", *(l-1));
	tl_current(*(l-1), 1);
	return ptr;
}

void *tl_realloc(char *file, int line, void *ptr, size_t size)
{
	int *o = (int*) ptr;
	int old = (o != NULL) ? *(o-1) : 0;
	void *newptr = realloc(ptr, size);
	int *l = (int*) newptr;
	printf("%s %d: realloc(%p, %d) = %p, ", file, line, newptr, size, ptr);
	printf("allocated %d bytes\n", *(l-1) - old);
	tl_current(*(l-1)-old, ptr ? 0 : 1);
	return newptr;
}

void tl_free(char *file, int line, void *ptr)
{
	int *l = (int*) ptr;
	printf("%s %d: free(%p), ", file, line, ptr);
	printf("freed %d bytes\n", *(l-1));
	tl_current(-(*(l-1)), -1);
	free(ptr);
}

void tl_current(int x, int y)
{
	static int current = 0;
	static int chunkes = 0;

	current += x;
	chunkes += y;
	printf("current: %d bytes (in %d chunkes)\n", current, chunkes);
}
#endif
