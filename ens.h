#ifndef __ENS_H
#define __ENS_H

#include "tunable.h"
#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include "nameser.h"
#include "utils.h"

/* ---------------------------- ENS error codes ----------------------------- */
#define CERROR_SUCCESS          0
#define CERROR_ARGNUM           1
#define CERROR_BADIP            2
#define CERROR_BADACL           3
#define CERROR_BADNAME          4
#define CERROR_TXTFMTERR        5
#define CERROR_INVALID          6
#define CERROR_NOMEM            7
#define CERROR_NOSPACE          8
#define CERROR_PERM		9
#define CERROR_MAX_CERROR	9

/* ---------------------------- DNS error codes ----------------------------- */
#define ERR_SUCCESSFUL          0
#define ERR_FORMAT              1
#define ERR_FAILURE             2
#define ERR_NAME                3
#define ERR_NOTIMPLEMENTED      4
#define ERR_REFUSED             5

/* ---------------------------- defines for add_rr() ------------------------ */
#define QD_SECTION              0
#define AN_SECTION              1
#define NS_SECTION              2
#define AR_SECTION              3

/* ---------------------------- return codes for ACL ------------------------ */
#define ACL_DENY		0
#define ACL_ALLOW		1

/* ---------------------------- verbosity levels ---------------------------- */
#define VERB_FORCE		0
#define VERB_LOW		1
#define VERB_MED		2
#define VERB_HIG		3
#define VERB_DEBUG		4

/* ---------------------------- return codes -------------------------------- */
#define YK_OK			0		/* Success */
#define YK_NOMEM		-1		/* Out of memory */
#define YK_INVALID		-2		/* Invalid argument */

/* ---------------------------- Defines ------------------------------------- */
#define HT_MAX_KEYSIZE  (MAXDNAME+10)

/* ---------------------------- macros -------------------------------------- */
/* ENS's perror */
#define perror(x) log(VERB_FORCE, "%s: %s\n", x, strerror(errno))

/* A simple way to trace memory leaks -- sorry if it seems obfustated code :) */
#ifdef TRACE_LEAKS
#ifdef 0
#define free(x) do { if (x != NULL) tl_allocated--; fprintf(logfp, "{FREE %p} (%s %d) %d\n", (x), __FILE__, __LINE__, tl_allocated); free(x); } while(0)
#define malloc(x) (tl_allocated++, fprintf(logfp, "{MALLOC %d} (%s %d) %d\n", (x), __FILE__, __LINE__, tl_allocated), (x <= 0) ? exit(1) : 0, malloc(x))
#define realloc(x, y) (tl_allocated = (x != NULL || y == 0) ? tl_allocated : tl_allocated+1, fprintf(logfp, "{REALLOC %p %d} (%s %d) %d\n", (x), (y), __FILE__, __LINE__, tl_allocated), realloc(x, y))
#endif
#define malloc(x) tl_malloc(__FILE__, __LINE__, x)
#define realloc(x, y) tl_realloc(__FILE__, __LINE__, x, y)
#define free(x) tl_free(__FILE__, __LINE__, x)

void *tl_malloc(char *file, int line, size_t size);
void *tl_realloc(char *file, int line, void *ptr, size_t size);
void tl_free(char *file, int line, void *ptr);
#endif

/* Verbose debugging messages */
#if YAKU_DEBUG
#define DEBUG(x) x
#else
#define DEBUG(x)
#endif

#define updatep(x) data += (x), data_size -= (x)

/* ---------------------------- types and strucutres ------------------------ */

/* Now we have our clear byte type, use it every times you need a byte
 * for something that isn't a string. */
typedef unsigned char byte;

/* A resource record */
struct RRentry {
	u_int32_t id;
	char *name;
	u_int16_t qtype;
	u_int16_t qclass;
	u_int32_t ttl;
	int size;
	byte *data;
	struct RRentry *next;
};

/* A note about the query_packet field:
 * We must save the query in order to resend it
 * to another external DNS server. */
struct forwardentry {
	char *name;
	u_int16_t qtype;
	u_int16_t qclass;
	u_int16_t id;
	u_int16_t orig_id;
	struct sockaddr_in clientaddr;
	time_t timestamp; /* for response timeout */
	int server_number;
	byte *query_packet;
	int query_size;
	struct forwardentry *prev;
	struct forwardentry *next;
};

/* This struct is used to store cached elements.
 * as you can see ENS save the response packet
 * without splitting it in many Resource Records.
 * This is really fast, but less flexible. */
struct cacheentry {
	char *name;
	u_int16_t qtype;
	u_int16_t qclass;
	int answer_size;
	byte *answer;
	u_int32_t ttl;
	time_t last_timestamp; /* time at the last access */
	time_t creat_timestamp; /* time at entry creation */
	time_t ttlupdate_timestamp; /* time of the last TTL update */
	int hits;
};

/* Structure used only to store the additional RRs needed for a response */
struct additionalrr {
	char *name;
	u_int16_t qtype;
	u_int16_t qclass;
};

/* Structure used for access control list */
struct acl {
	char rule[RULE_MAXSIZE]; /* xxx.yyy.zzz.kkk + $ + nulterm */
	struct acl *next;
};

/* Structures for supported RR types */
struct RR_A {
	char addr[4];
};

struct RR_MX {
	u_int16_t preference;
	/* variable size exchange name */
};

struct RR_SOA {
	/* variable size dns name */
	/* variable size mailbox name */
	u_int32_t serial;
	u_int32_t refresh;
	u_int32_t retry;
	u_int32_t expire;
	u_int32_t minimum;
};

/* the RR_PTR struct is not needed since the PTR is just a name */
/* the RR_TXT struct is not needed since the TXT is just the text */
/* the RR_TXT struct is not needed since the NS is just a name */

/* main lists */
extern struct hashtable cache_table;
extern struct hashtable forward_table;
extern struct hashtable local_table;

/* more global stuff */

/* Options */
extern int opt_cachenoexpire;
extern int opt_daemon;
extern int opt_axfr;
extern int opt_tcp_requests_for_connection;
extern int opt_axfr_compatmode;
extern int opt_uptime;
extern int opt_autoptr;
extern int opt_logtime;
extern int opt_forward;
extern int opt_cache;
extern int opt_logfile;
extern int opt_bindaddr;
extern int opt_verbose;
extern int opt_wildcard;
extern char *configfile;
extern char *safeuser;
extern char bindaddr[16];

/* Sockets & co. */
extern int s;
extern int tcp_s;
extern int opt_udp_port;
extern int opt_tcp_port;

/* Log filedes and filename */
extern FILE *logfp;
extern char logfile[1024];

/* forwarding */
extern struct in_addr forward_server[MAX_FORWARD_SERVERS];
extern int forward_server_count;
extern u_int16_t forward_id;
extern int forward_count;
extern int forward_max;
extern int forward_timeout;
extern int next_server_timeout;
extern int dns_forward_port;

/* cache */
extern unsigned int cache_count;
extern unsigned int cache_max;
extern unsigned int cache_maxttl;
extern unsigned int cache_minttl;

/* misc */
extern int ens_awake_time_sec;
extern int ens_awake_time_usec;
extern char *cerror_list[];
extern u_int32_t local_ttl;
extern u_int16_t local_class;
#ifdef TRACE_LEAKS
extern int tl_allocated;
#endif
extern int securelevel;
extern time_t ens_start;

/* Chroot jail vars */
extern char chrootjail[1024];
extern int opt_chroot;

/* ENS ACL */
extern struct acl *acl_dns_allow_head;
extern struct acl *acl_dns_allow_tail;
extern struct acl *acl_dns_deny_head;
extern struct acl *acl_dns_deny_tail;
extern struct acl *acl_fwd_allow_head;
extern struct acl *acl_fwd_allow_tail;
extern struct acl *acl_fwd_deny_head;
extern struct acl *acl_fwd_deny_tail;
extern struct acl *acl_axfr_allow_head;
extern struct acl *acl_axfr_allow_tail;
extern struct acl *acl_axfr_deny_head;
extern struct acl *acl_axfr_deny_tail;

/* statistics */
extern unsigned int statistic_received_packet;
extern unsigned int statistic_invalid_packet;
extern unsigned int statistic_query_count;
extern unsigned int statistic_iquery_count;
extern unsigned int statistic_response_count;

/* Function prototypes */

/*********
 * dns.c *
 *********/
byte *name_encode(char *msg, int *size, char sep);
int name_decode(byte *ptr, int data_size, byte *base, char **name, int compr);
void send_udp_error(int fd, struct sockaddr *from, int fromlen, byte *packet, unsigned int size, int error_type);
byte *build_error(int *retsize, byte *packet, unsigned int size, int error_type);
int build_header(byte **dest, HEADER *hdr, int aa);
int send_udp(int fd, void *packet, unsigned int size, struct sockaddr *to, int tolen);
int send_tcp(byte *packet, int len, int sd);
u_int32_t get_min_ttl(byte *packet, unsigned int packet_size);
void dns_shuffle(byte *packet, unsigned int packet_size);
void fix_ttl(byte *packet, unsigned int packet_size, time_t last_fix, time_t now);

/**************
 * response.c *
 **************/
byte *build_response(u_int16_t qclass, u_int16_t qtype, char *qname, char *name, byte *query, int query_size, HEADER *hdr, int *size, int maxsize);

/***********
 * misc .c *
 ***********/
char *qtype_to_str(unsigned short qtype);
char *qclass_to_str(unsigned short qclass);
int line_splitter(char *buffer, char *commandargs[], int argmax);
time_t get_sec(void);
void dump_state(void);
u_int16_t get_rand_id(void);

/************
 * config.c *
 ************/
int config_read(char *filename);
void config_reset(void);
char *config_process_line(char *line);
char *strcerror(int cerror);

/***********
 * local.c *
 ***********/
struct RRentry *alloc_rr(char *name, u_int16_t qtype, u_int16_t qclass, unsigned int size);
int add_rr(byte **dest, HEADER *hdr, struct RRentry *rr, unsigned int size, int section, int maxsize);
void local_free(void);
int local_add_entry(struct RRentry *rr);
int local_add_A(char *name, char *addr);
int local_add_MX(char *name, char *priority, char *exchange);
int local_add_PTR(char *name, char *ptr);
int local_add_CNAME(char *name, char *canonical);
int local_add_NS(char *name, char *ns);
int local_add_TXT(char *argv[]);
int local_add_SOA(int argc, char **argv);
void local_putontop(struct RRentry *prev, struct RRentry *rr);
struct RRentry *local_search(char *name, u_int16_t qtype, u_int16_t qclass,
					 u_int32_t seq);
int local_search_all(char *name, u_int16_t qtype, u_int16_t qclass,
				struct RRentry **rra, unsigned int size);
void local_init(void);

/**********
 * unix.c *
 **********/
void daemon_init(void);

/************
 * signal.c *
 ************/
void signal_handler(int signum);
void install_signal_handler(void);
void (*Signal(int signo, void (*func)(int)))(int);
int signal_block(int sig);
int signal_unblock(int sig);
int handle_signals(void);

/*************
 * forward.c *
 *************/
void forward_free_entry(struct forwardentry *entry);
void forward_free_expired(void);
void forward_request(HEADER *hdr, char *packet, unsigned int size, struct sockaddr *from, char *name, u_int16_t qtype, u_int16_t qclass);
struct forwardentry *forward_search(int id, int qtype, int qclass, char *name,
							unsigned int *index);
void forward_free_by_index(unsigned int index);
void forward_init(void);

/***********
 * cache.c *
 ***********/
void cache_add_entry(struct forwardentry *p, byte *packet, int packet_size);
struct cacheentry *cache_search_entry(char *name, int qclass, int qtype);
void cache_free_entry(struct cacheentry *entry, struct cacheentry *previous);
void cache_free_oldest(void);
int cache_free_expired(void);
void cache_fix_ttl(struct cacheentry *cache);
void cache_shuffle(struct cacheentry *cache);
void cache_init(void);

/*********
 * arr.c *
 *********/
int additional_rr_needed(struct additionalrr *arr, struct RRentry *rr, int arrindex);

/*********
 * acl.c *
 *********/
void acl_add_rule(char *rule, struct acl **head, struct acl **tail);
void acl_free(void);
int acl_check_dns(char *ip);
int acl_check_fwd(char *ip);
int acl_check_dyn(char *ip);
int acl_check_axfr(char *ip);

/**************
 * axfr_out.c *
 **************/
int axfr_init(void);
void tcp_handler(void);

/*********
 * log.c *
 *********/
int log(int level, char *fmt, ...);
int log_flush(void);
void open_logfile(char *filename);

/************
 * uptime.c *
 ************/
int uptime_refresh(void);

/*************
 * autoptr.c *
 *************/
int inet_toinaddr(char *addr, char *dest);

/***********
 * htkey.c *
 ***********/
size_t rr_to_key(char *dest, size_t dsize, char *name, u_int16_t type,
		u_int16_t class, u_int32_t seq);
int ht_dnskey_compare(void *key1, void *key2);
u_int32_t ht_dnskey_hash(void *key);

/*************************
 * strlcpy.c & strlcat.c *
 *************************/
size_t strlcpy(char *dst, const char *src, size_t siz);
size_t strlcat(char *dst, const char *src, size_t siz);

/************
 * rlimit.c *
 ************/
int set_core_size(unsigned int size);

#endif /* __ENS_H */
