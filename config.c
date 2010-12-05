/* config.c
 * Configuration-related code
 *
 * Copyright (C) 2000,2001,2002 by Salvatore Sanfilippo
 * <antirez@invece.org>
 *
 * This code is under the GPL license version 2
 * See the COPYING file for more information
 */

/* ens.h must be included before all other includes */
#include "ens.h"

#include <string.h>
#include <stdlib.h>

/* not exported functions */
static void config_error(int linenum, char *line, char *errormsg);
static int op_include(int argc, char **argv);
static int op_forwarder(int argc, char **argv);
static int op_forward_max(int argc, char **argv);
static int op_forward_entry_timeout(int argc, char **argv);
static int op_forward_next_timeout(int argc, char **argv);
static int op_cache_max(int argc, char **argv);
static int op_cache_minttl(int argc, char **argv);
static int op_cache_maxttl(int argc, char **argv);
static int op_logfile(int argc, char **argv);
static int op_loglevel(int argc, char **argv);
static int op_ttl(int argc, char **argv);
static int op_class(int argc, char **argv);
static int op_acl(int argc, char **argv);
static int op_cname(int argc, char **argv);
static int op_mx(int argc, char **argv);
static int op_ptr(int argc, char **argv);
static int op_txt(int argc, char **argv);
static int op_ns(int argc, char **argv);
static int op_soa(int argc, char **argv);
static int op_a(int argc, char **argv);
static int op_tcp_requests_for_connection(int argc, char **argv);
static int op_generic_enable_disable(int argc, char **argv);

/* exported functions */
void config_reset(void);
int config_read(char *filename);
char *config_process_line(char *line);
char *strcerror(int cerror);

static struct config_op {
	char *cmd;
	int argc;
	int (*op)(int argc, char **argv);
} config_table[] = {
	{"include", 2, op_include},
	{"logfile", 2, op_logfile},
	{"loglevel", 2, op_loglevel},
	{"acl", -1, op_acl},
	{"uptime", 1, op_generic_enable_disable},
	{"nologtime", 1, op_generic_enable_disable},
	{"wildcard_lookup", 1, op_generic_enable_disable},
	{"nameserver", 2, op_forwarder},
	{"forward_max", 2, op_forward_max},
	{"forward_entry_timeout", 2, op_forward_entry_timeout},
	{"forward_next_timeout", 2, op_forward_next_timeout},
	{"cache_max", 2, op_cache_max},
	{"cache_minttl", 2, op_cache_minttl},
	{"cache_maxttl", 2, op_cache_maxttl},
	{"cache_noexpire", 1, op_generic_enable_disable},
	{"ttl", 2, op_ttl},
	{"class", 2, op_class},
	{"a", 3, op_a},
	{"cname", 3, op_cname},
	{"mx", 4, op_mx},
	{"ptr", 3, op_ptr},
	{"txt", -3, op_txt},
	{"ns", 3, op_ns},
	{"soa", 9, op_soa},
	{"autoptr", 1, op_generic_enable_disable},
	{"noautoptr", 1, op_generic_enable_disable},
	{"axfr_more_rr", 1, op_generic_enable_disable},
	{"tcp_requests_for_connection", 2, op_tcp_requests_for_connection},
	{NULL, 0, NULL}
};

char *cerror_list[] = {
	"Success",					/* 0 */
	"Wrong number of arguments",			/* 1 */
	"Bad IP address",				/* 2 */
	"Bad ACL",					/* 3 */
	"Bad domain name",				/* 4 */
	"TXT format error, label too long?",		/* 5 */
	"Invalid argument",				/* 6 */
	"Out of memory",				/* 7 */
	"No space left",				/* 8 */
	"Permission denied"				/* 9 */
};

char *strcerror(int cerror)
{
	if (cerror < 0 || cerror > CERROR_MAX_CERROR)
		return "Unknown error";
	return cerror_list[cerror];
}

char *config_process_line(char *line)
{
	int line_argc, cerror;
	char *line_argv[LINEARGS_MAX+1];
	struct config_op *cop = config_table;
	char *e = "Unknown RR type";

	line_argc = line_splitter(line, line_argv, LINEARGS_MAX);
	if (line_argc == 0) {
		(void) line_splitter(NULL, line_argv, 0); /* free */
		return NULL;
	}
	while(cop->cmd) {
		if (!strcasecmp(line_argv[0], cop->cmd)) {
			e = NULL;
			if ((cop->argc > 0 && line_argc != cop->argc) ||
			    (cop->argc < 0 && line_argc < -cop->argc)) {
				e = strcerror(CERROR_ARGNUM);
				break;
			}
			cerror = cop->op(line_argc, line_argv);
			if (cerror != CERROR_SUCCESS) {
				e = strcerror(cerror);
				break;
			}
			break;
		}
		cop++;
	}
	(void) line_splitter(NULL, line_argv, 0); /* free */
	return e;
}

int config_read(char *filename)
{
	FILE *fp;
	char line[1024];
	int line_count = 1;

	if (!strcmp(filename, "-") && !opt_daemon) {
		fp = stdin;
	} else {
		fp = fopen(filename, "r");
		if (fp == NULL) {
			ylog(VERB_FORCE, "Can't open the config file %s\n",
				filename);
			perror("fopen");
			ylog(VERB_FORCE, "Remember that you MUST "
					"specify the absolute path\n");
			exit(1);
		}
	}
	while (fgets(line, 1024, fp) != NULL) {
		char *e;
		if (line[0] == '#') {
			line_count++;
			continue;
		}
		if ((e = config_process_line(line)) != NULL)
			config_error(line_count, line, e);
		line_count++;
	}
	if (fp != stdin)
		fclose(fp);
	return 0;
}

static void config_error(int linenum, char *line, char *errormsg)
{
	ylog(VERB_FORCE, "--\n`%s' at line %d\n", errormsg, linenum);
	ylog(VERB_FORCE, "%d: %s--\n", linenum, line);
	exit(1);
}

void config_reset(void)
{
	opt_forward = 0;
	forward_server_count = 0;
	opt_logtime = 1;
	local_free();
	acl_free();
}

static int op_include(int argc, char **argv)
{
	ARG_UNUSED(argc)

	if (securelevel >= 1)
		return CERROR_PERM;
	ylog(VERB_HIG, "> include %s\n", argv[1]);
	config_read(argv[1]);
	ylog(VERB_HIG, "< end of inclusion of %s\n", argv[1]);
	return CERROR_SUCCESS;
}

static int op_forwarder(int argc, char **argv)
{
	ARG_UNUSED(argc)

	if (forward_server_count == MAX_FORWARD_SERVERS)
		return CERROR_NOSPACE;
	if (inet_aton(argv[1],
	    &forward_server[forward_server_count]) == 0)
		return CERROR_BADIP;
	opt_forward = 1;
	ylog(VERB_HIG, "(forwarding) external server: %s\n", argv[1]);
	forward_server_count++;
	/* accept responses from this external server */
	acl_add_rule(argv[1], &acl_dns_allow_head, &acl_dns_allow_tail);
	return CERROR_SUCCESS;
}

static int op_forward_max(int argc, char **argv)
{
	ARG_UNUSED(argc)

	forward_max = atoi(argv[1]);
	if (forward_max <= 0) {
		forward_max = 0;
		opt_forward = 0;
		ylog(VERB_MED, "forwarding disabled\n");
	} else {
		ylog(VERB_HIG, "forwarding: max queue %d\n", forward_max);
	}
	return CERROR_SUCCESS;
}

static int op_forward_entry_timeout(int argc, char **argv)
{
	ARG_UNUSED(argc)

	forward_timeout = atoi(argv[1]);
	if (forward_timeout <= 0) {
		return CERROR_INVALID;
	} else {
		ylog(VERB_HIG, "forwarding: entry timeout %d\n", forward_timeout);
	}
	return CERROR_SUCCESS;
}

static int op_forward_next_timeout(int argc, char **argv)
{
	ARG_UNUSED(argc)

	next_server_timeout = atoi(argv[1]);
	if (next_server_timeout < 0) {
		return CERROR_INVALID;
	} else {
		ylog(VERB_HIG, "forwarding: next server timeout %d\n",
			next_server_timeout);
	}
	return CERROR_SUCCESS;
}

static int op_cache_max(int argc, char **argv)
{
	ARG_UNUSED(argc)

	cache_max = atoi(argv[1]);
	if (cache_max <= 0) {
		cache_max = 0;
		opt_cache = 0;
		ylog(VERB_MED, "cache: disabled\n");
	} else {
		ylog(VERB_HIG, "cache: max size %d\n", cache_max);
	}
	return CERROR_SUCCESS;
}

static int op_cache_minttl(int argc, char **argv)
{
	ARG_UNUSED(argc)

	cache_minttl = atoi(argv[1]);
	ylog(VERB_HIG, "cache: min TTL %d\n", cache_minttl);
	return CERROR_SUCCESS;
}

static int op_cache_maxttl(int argc, char **argv)
{
	ARG_UNUSED(argc)

	cache_maxttl = atoi(argv[1]);
	ylog(VERB_HIG, "cache: max TTL %d\n", cache_maxttl);
	return CERROR_SUCCESS;
}

static int op_logfile(int argc, char **argv)
{
	ARG_UNUSED(argc)

	if (securelevel >= 1)
		return CERROR_PERM;
	strlcpy(logfile, argv[1], 1024);
	opt_logfile = 1;
	return CERROR_SUCCESS;
}

static int op_loglevel(int argc, char **argv)
{
	ARG_UNUSED(argc)

	if (securelevel >= 1)
		return CERROR_PERM;
	if (!strcasecmp(argv[1], "errors")) {
		opt_verbose = VERB_FORCE;
	} else if (!strcasecmp(argv[1], "low")) {
		opt_verbose = VERB_LOW;
	} else if (!strcasecmp(argv[1], "med")) {
		opt_verbose = VERB_MED;
	} else if (!strcasecmp(argv[1], "high")) {
		opt_verbose = VERB_HIG;
	} else if (!strcasecmp(argv[1], "debug")) {
		opt_verbose = VERB_DEBUG;
	} else {
		return CERROR_INVALID;
	}
	return CERROR_SUCCESS;
}

static int op_ttl(int argc, char **argv)
{
	ARG_UNUSED(argc)

	local_ttl = atoi(argv[1]);
	ylog(VERB_HIG, "> Time To Live is %u\n", local_ttl);
	return CERROR_SUCCESS;
}

static int op_tcp_requests_for_connection(int argc, char **argv)
{
	ARG_UNUSED(argc)

	opt_tcp_requests_for_connection = atoi(argv[1]);
	ylog(VERB_HIG, "TCP requests for connection set to %d\n",
			opt_tcp_requests_for_connection);
	return CERROR_SUCCESS;
}

static int op_class(int argc, char **argv)
{
	ARG_UNUSED(argc)

	if (!strcasecmp(argv[1], "IN")) {
		local_class = C_IN;
		ylog(VERB_HIG, "> Class is IN\n");
	} else if (!strcasecmp(argv[1], "CHAOS")) {
		local_class = C_CHAOS;
		ylog(VERB_HIG, "> Class is CHAOS\n");
	} else if (!strcasecmp(argv[1], "ANY")) {
		local_class = C_ANY;
		ylog(VERB_HIG, "> Class is ANY\n");
	} else {
		return CERROR_INVALID;
	}
	return CERROR_SUCCESS;
}

static int op_acl(int argc, char **argv)
{
	char *rule_accept = "0123456789.$";
	struct acl **head, **tail;
	int j;

	/* select the acl list */
	if (!strcasecmp("dns.allow", argv[1])) {
		head = &acl_dns_allow_head;
		tail = &acl_dns_allow_tail;
	} else if (!strcasecmp("dns.deny", argv[1])) {
		head = &acl_dns_deny_head;
		tail = &acl_dns_deny_tail;
	} else if (!strcasecmp("fwd.allow", argv[1])) {
		head = &acl_fwd_allow_head;
		tail = &acl_fwd_allow_tail;
	} else if (!strcasecmp("fwd.deny", argv[1])) {
		head = &acl_fwd_deny_head;
		tail = &acl_fwd_deny_tail;
	} else if (!strcasecmp("axfr.allow", argv[1])) {
		head = &acl_axfr_allow_head;
		tail = &acl_axfr_allow_tail;
	} else if (!strcasecmp("axfr.deny", argv[1])) {
		head = &acl_axfr_deny_head;
		tail = &acl_axfr_deny_tail;
	} else {
		return CERROR_BADACL;
	}

	for (j = 2; j < argc; j++) {
		if ((strlen(argv[j]) >= RULE_MAXSIZE) ||
		(strspn(argv[j], rule_accept) != strlen(argv[j])) ||
		(strchr(argv[j], '$') && argv[j][strlen(argv[j])-1] != '$') ||
		(strchr(argv[j], '$') != strrchr(argv[j], '$'))) {
			return CERROR_BADACL;
		}
		acl_add_rule(argv[j], head, tail);
		ylog(VERB_HIG, "acl: loaded %s %s\n", argv[1], argv[j]);
	}
	return CERROR_SUCCESS;
}

static int op_mx(int argc, char **argv)
{
	ARG_UNUSED(argc)

	if (local_add_MX(argv[1], argv[2], argv[3]) == -1)
		return CERROR_BADNAME;
	return CERROR_SUCCESS;
}

static int op_ptr(int argc, char **argv)
{
	ARG_UNUSED(argc)

	if (local_add_PTR(argv[1], argv[2]) == -1)
		return CERROR_BADNAME;
	return CERROR_SUCCESS;
}

static int op_txt(int argc, char **argv)
{
	ARG_UNUSED(argc)

	if (local_add_TXT(argv) == -1)
		return CERROR_TXTFMTERR;
	return CERROR_SUCCESS;
}

static int op_ns(int argc, char **argv)
{
	ARG_UNUSED(argc)

	if (local_add_NS(argv[1], argv[2]) == -1)
		return CERROR_BADNAME;
	return CERROR_SUCCESS;
}

static int op_cname(int argc, char **argv)
{
	ARG_UNUSED(argc)

	if (local_add_CNAME(argv[1], argv[2]) == -1)
		return CERROR_BADNAME;
	return CERROR_SUCCESS;
}

static int op_soa(int argc, char **argv)
{
	if (local_add_SOA(argc, argv) == -1)
		return CERROR_BADNAME;
	return CERROR_SUCCESS;
}

static int op_a(int argc, char **argv)
{
	int retval;
	char tmp[32];
	ARG_UNUSED(argc);

	retval = local_add_A(argv[1], argv[2]);
	if (retval == -1)
		return CERROR_BADNAME;
	if (opt_autoptr) {
		if ((retval = inet_toinaddr(argv[2], tmp)) != 0)
			return retval;
		strlcat(tmp, ".", 32);
			tmp[strlen(tmp)-1] = '\0';
			if (local_add_PTR(tmp, argv[1]) == -1)
				return CERROR_BADNAME;
	}
	return CERROR_SUCCESS;
}

static int op_generic_enable_disable(int argc, char **argv)
{
	ARG_UNUSED(argc)

	if (strcasecmp(argv[0], "nologtime") == 0)
		opt_logtime = 0;
	else if (strcasecmp(argv[0], "autoptr") == 0)
		opt_autoptr = 1;
	else if (strcasecmp(argv[0], "noautoptr") == 0)
		opt_autoptr = 0;
	else if (strcasecmp(argv[0], "uptime") == 0)
		opt_uptime = 1;
	else if (strcasecmp(argv[0], "cache_noexpire") == 0)
		opt_cachenoexpire = 1;
	else if (strcasecmp(argv[0], "axfr_more_rr") == 0)
		opt_axfr_compatmode = 0;
	else if (strcasecmp(argv[0], "wildcard_lookup") == 0)
		opt_wildcard = 1;

	return CERROR_SUCCESS;
}
