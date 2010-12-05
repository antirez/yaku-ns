/* core.c
 * The core of yaku-ns
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

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "nameser.h"
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <sys/stat.h> /* umask(2) */
#include <pwd.h>
#include <grp.h>
#include <sys/time.h>
#include <stdlib.h>
#include <signal.h>

/* more global stuff */
char logfile[1024];
int opt_forward = 0;
int opt_cache = 1;
int opt_logfile = 0;
int opt_bindaddr = 0;
int opt_wildcard = 0;
int s;				/* the UDP socket */
int opt_udp_port = DNS_PORT;
char *configfile = CONFIG_FILE;
char *safeuser = SAFEUSER;
int next_server_timeout = NEXT_SERVER_TIMEOUT;
int ens_awake_time_sec = ENS_AWAKE_TIME_SEC;
int ens_awake_time_usec = ENS_AWAKE_TIME_USEC;
char bindaddr[16];
int securelevel = 0;

char chrootjail[1024];
int opt_chroot = 0;
int opt_daemon = 0;

/* statistics */
unsigned int statistic_received_packet = 0;
unsigned int statistic_invalid_packet = 0;
unsigned int statistic_query_count = 0;
unsigned int statistic_iquery_count = 0;
unsigned int statistic_response_count = 0;

/* not exported functions */
static void initialize(void);
static void core(void);
static int scheduler(void);
static void packet_processor(byte *packet, unsigned int size,
		struct sockaddr *from, socklen_t fromlen);
static void response_processor(byte *packet, unsigned int size,
		struct sockaddr *from, socklen_t fromlen);
static void query_processor(byte *packet, unsigned int size,
		struct sockaddr *from, socklen_t fromlen);

#ifdef PROFILING
unsigned long long get_clock(void)
{
	unsigned long long int x;
	__asm__ volatile (".byte 0x0f, 0x31" : "=A" (x));
	return x;
}
#endif
#ifdef TRACE_LEAKS
int tl_allocated = 0;
void *tl_ptr;
#endif

int main(int argc, char **argv)
{
	int c;

	/* default is to logs to standard output */
	logfp = stdout;
	while ((c = getopt(argc, argv, "p:P:f:C:F:T:c:u:l:r:b:xdhV")) != EOF) {
		switch(c) {
		case 'p':
			opt_udp_port = atoi(optarg);
			break;
		case 'P':
			opt_tcp_port = atoi(optarg);
			break;
		case 'C':
			cache_max = atoi(optarg);
			if (cache_max == 0)
				opt_cache = 0;
			break;
		case 'f':
			dns_forward_port = atoi(optarg);
			break;
		case 'F':
			forward_max = atoi(optarg);
			if (forward_max == 0)
				opt_forward = 0;
			break;
		case 'T':
			forward_timeout = atoi(optarg);
			break;
		case 'c':
			configfile = optarg;
			break;
		case 'u':
			safeuser = optarg;
			break;
		case 'l':
			strlcpy(logfile, optarg, 1024);
			opt_logfile = 1;
			break;
		case 'r':
			strlcpy(chrootjail, optarg, 1024);
			opt_chroot = 1;
			break;
		case 'd':
			opt_daemon = 1;
			break;
		case 'b':
			strlcpy(bindaddr, optarg, 16);
			opt_bindaddr = 1;
			break;
		case 'x':
			opt_axfr = 1;
			break;
		case 'V':
			opt_verbose++;
			break;
		case 'h':
		default:
			printf(
"usage: ens [-p <port>] [-P <port>] [-f <port>] [-C <max>] [-F <max>]\n"
"           [-T <forward_timeout>] [-c <config_file>]\n"
"           [-l <logfile>] [-r <chroot jail>] [-u owner]\n"
"           [-b <addr>] [-xdhV]\n"
			);
			exit(1);
		}
	}

	/* Initialization of random stuff and enter the main loop */
	initialize();
	core();

	return 0; /* unreached */
}

/* Create and bind the UDP socket */
#define DNS_SNDBUF	65536
#define DNS_RCVBUF	65536
int net_init(void)
{
	struct sockaddr_in sa;
	int retval;
	int size;
        socklen_t optsize;

	/* open the main UDP socket */
	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s == -1) {
		perror("socket");
		return -1;
	}

	/* Enlarge the input and output socket buffers:
	 * this can help with high latency. */
	optsize = sizeof(size);
	if (getsockopt(s, SOL_SOCKET, SO_RCVBUF, &size, &optsize) == -1 ||
	    size < DNS_RCVBUF) {
		size = DNS_RCVBUF;
		if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size))
			== -1) {
			perror("[net_init] setsockopt");
			/* not fatal */
		}
	}

	optsize = sizeof(size);
	if (getsockopt(s, SOL_SOCKET, SO_SNDBUF, &size, &optsize) == -1 ||
	    size < DNS_SNDBUF) {
		size = DNS_SNDBUF;
		if (setsockopt(s, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size))
			== -1) {
			perror("[net_init] setsockopt");
			/* not fatal */
		}
	}

	/* bind the socket */
	sa.sin_family = AF_INET;
	sa.sin_port = htons(opt_udp_port);
	if (!opt_bindaddr) {
		sa.sin_addr.s_addr = htonl(INADDR_ANY); /* all interfaces */
	} else {
		struct in_addr tmp;
		if (inet_aton(bindaddr, &tmp) == 0) {
			ylog(VERB_FORCE, "[main] bad IP address to bind\n");
			return -1;
		}
		sa.sin_addr.s_addr = tmp.s_addr;
	}
	retval = bind(s, (struct sockaddr*) &sa, sizeof(sa));
	if (retval == -1) {
		perror("bind");
		return -1;
	}
	return 0;
}

/* Chroot & root dropping */
int security_init(void)
{
	struct passwd *pw;

	/* drop root priviledges and chroot */
	if (getuid() == 0) {
		pw = getpwnam(safeuser);
		if (!pw) {
			ylog(VERB_FORCE, "[main] getpwnam error, does user '%s' exist?\n",
				safeuser);
			exit(1);
		}

		/* chroot jail -- just after the getpwnam that needs passwd */
		if (opt_chroot && (chdir (chrootjail) == -1 ||
				  chroot(chrootjail) == -1))
		{
			perror("chdir/chroot");
			exit(1);
		}
		/* root squashing */	
		if (setgroups(0, NULL) == -1 ||
			setgid(pw->pw_gid) == -1 ||
			setuid(pw->pw_uid) == -1) {
				perror("[main] setgroups/setgid/setuid");
				exit(1);
			}

		ylog(VERB_MED, "switched to user '%s'\n", safeuser);
	}
	return 0;
}

static void initialize(void)
{
	ylog(VERB_LOW, "DNS server started, verbosity set to %d\n",
		opt_verbose);

	/* for the uptime */
	ens_start = get_sec();

	/* Initialization */
	set_core_size(YK_CORE_SIZE);
	if (opt_daemon)
		daemon_init();

	/* If the user did not specified a log file using
	 * the command line switch, but demonization is on,
	 * ENS will not write the log to standard output,
	 * This behaviour may be overrided by the configuration
	 * file that will be read below. */
	if (opt_daemon && !opt_logfile)
		logfp = NULL;

	/* It's safe to change the directory to / and
	 * set the umask to 2 (even if actually ENS
	 * never creates files). */
	if (chdir("/") == -1)
		perror("WARNING: chdir to / failed");
	(void) umask(2);

	install_signal_handler();
	/* We want this signals delivered only in a safe point */
	signal_block(SIGHUP);
	signal_block(SIGUSR1);
	signal_block(SIGUSR2);

	/* Net initialization */
	if (net_init() == -1) {
		ylog(VERB_FORCE, "[initialize] Net initialization failed\n");
		exit(1);
	}

	/* Initialize DNS over TCP for AXFR requests */
	if (opt_axfr && axfr_init() == -1) {
		ylog(VERB_FORCE, "[initialize] failed initializing AXFR\n");
		opt_axfr = 0;
		/* This isn't fatail */
	}

	/* Security initialization */
	if (security_init() == -1) {
		ylog(VERB_FORCE, "[initialize] Security initialization "
				"failed\n");
		exit(1);
	}

	local_init(); /* Initialize the local table */
	cache_init(); /* Initialize the cache table */
	forward_init(); /* Initialize the forward table */

	/* read the config file -- note that we dropped root privileges
	 * and chrooted ENS before to read the config file */
	config_reset();
	config_read(configfile);
	/* open the log file */
	if (opt_logfile)
		open_logfile(logfile);

	ylog(VERB_LOW, "Local resource records loaded\n");
}

/* The DNS server main loop */
static void core(void)
{
	byte packet[PACKETSZ]; /* readed UDP packet */

	while(1) {
		int size;
		struct sockaddr_in from;
		socklen_t fromlen;
		fd_set rfds;
		struct timeval tv;
		int t;
		int maxfd = s;
#ifdef PROFILING
		static unsigned long long saved_clock = 0, new_clock;
#endif

		signal_unblock(SIGHUP);
		signal_unblock(SIGUSR1);
		signal_unblock(SIGUSR2);
		signal_unblock(SIGCHLD);
		/* The OS should delivery this signals here */
		signal_block(SIGHUP);
		signal_block(SIGUSR1);
		signal_block(SIGUSR2);
		signal_block(SIGCHLD);

		/* scheduler() runs some CPU expansive task
		 * at a given period */
		(void) scheduler();

		FD_ZERO(&rfds);
		FD_SET(s, &rfds);

		if (opt_axfr) {
			FD_SET(tcp_s, &rfds);
			if (tcp_s > maxfd)
				maxfd = tcp_s;
		}

		tv.tv_sec = ens_awake_time_sec;
		tv.tv_usec = ens_awake_time_usec;

		/* DNS core handler */
#ifdef PROFILING
		new_clock = get_clock();
		printf("CLOCKS: %Lu\n", new_clock - saved_clock);
#endif
		t = select(maxfd+1, &rfds, NULL, NULL, &tv);
#ifdef PROFILING
		saved_clock = get_clock();
#endif
		if (t == -1) {
			if (errno != EINTR)
				perror("select");
			continue;
		}

		/* Handle DNS over UDP requests */
		if (FD_ISSET(s, &rfds)) {
			fromlen = sizeof(struct sockaddr_in);
			size = recvfrom(s, packet, PACKETSZ, 0,
				(struct sockaddr*)&from, &fromlen);
			if (size == -1) {
				perror("recv");
				continue;
			}
			statistic_received_packet++;
			DEBUG(ylog(VERB_DEBUG, "Packet received\n");)
			packet_processor(packet, size, (struct sockaddr*)&from, fromlen);
		}

		/* Handle DNS over TCP requests (ony AXFR) */
		if (opt_axfr && FD_ISSET(tcp_s, &rfds))
			tcp_handler();
	}
}

/* scheduler():
 * This function ensure that if we call it many times
 * in one second it'll perform some operation only at
 * a given period. */
static int scheduler(void)
{
	static time_t scheduler_next = 0;
	static time_t cache_next = 0;
	static time_t hash_resize_next = 0;
	time_t now = get_sec();
	int ran = 0;

	/* Anyway don't run nothing more than one time in a second
	 * (actually it may run it two times in the same second in the
	 * worst case) */
	if (now >= scheduler_next) {
		/* Call the handler for the signals that's unsafe
		 * to handle asyncronously */
		(void) handle_signals();

		/* We must call forward_free_expired() every
		 * second or so, the function also resend the
		 * requests in timeout to the next forwarder */
		if (opt_forward && forward_timeout) {
			forward_free_expired();
			ran++;
		}
		if (opt_cache) {
			/* Free the expired entries in the cache table
			 * Individual cached responses
			 * are freed anyway if someone want to get
			 * they using cache_search_entry().
			 * Anyway to free *all* the entries expired
			 * is usefull if the DNS server runs under
			 * very low traffic in some period of the day,
			 * to free memory for other processes.
			 * WARNING: cache_free_expired() is very
			 * CPU expansive, don't schedule it too often */
			if (now >= cache_next) {
				cache_free_expired();
				cache_next = now + SCHEDULE_CACHE_EXPIRE;
				ran++;
			}
		}
		/* Resize the hash tables */
		if (now >= hash_resize_next) {
			if (opt_cache) {
				unsigned int old_size = cache_table.size;

				ht_resize(&cache_table);
				ylog(VERB_HIG, "Cache table resize (%u -> %u)\n",
					old_size, cache_table.size);
			}
			if (opt_forward) {
				unsigned int old_size = forward_table.size;

				ht_resize(&forward_table);
				ylog(VERB_HIG, "Forward table resize "
					      "(%u -> %u)\n",
					old_size, forward_table.size);
			}
			hash_resize_next = now + SCHEDULE_HASH_RESIZE;
		}

		if (opt_uptime)
			uptime_refresh();
		/* flush the logs */
		log_flush();
		/* Re-get the time to strip out the time consumed */
		scheduler_next = get_sec() + SCHEDULE_SCHEDULER;
	}
	return ran;
}

/* This function pass the control to the right function */
static void packet_processor(byte *packet, unsigned int size, struct sockaddr *from, socklen_t fromlen)
{
	struct sockaddr_in *in = (struct sockaddr_in *) from;
	char straddr[64];
	HEADER *hdr = (HEADER*) packet;

	/* Check the ACL */
	strlcpy(straddr, inet_ntoa(in->sin_addr), 64);
	if (acl_check_dns(straddr) == ACL_DENY) {
		ylog(VERB_MED, "DNS Access denied to client %s-%d\n",
			straddr, ntohs(in->sin_port));
		send_udp_error(s, (struct sockaddr*) from,
			fromlen, packet, size, ERR_REFUSED);
		return;
	}

	/* SANITYCHECK: size is < of the DNS header size */
	if (size < sizeof(HEADER)) {
		DEBUG(ylog(VERB_DEBUG, "Packet too short\n");)
		return;
	}

	/* The DNS is a response? call response_processor() */
	if (hdr->qr == 1) {
		statistic_response_count++;
		response_processor(packet, size, from, fromlen);
		return;
	}

	/* is a query, shunt the opcodes */
	switch (hdr->opcode) {
	case QUERY:
		statistic_query_count++;
		query_processor(packet, size, from, fromlen);
		break;
	case IQUERY: /* NOT IMPLEMENTED */
		statistic_iquery_count++;
		DEBUG(ylog(VERB_DEBUG, "Iquery received\n");)
		send_udp_error(s, from, fromlen, packet, size, ERR_NOTIMPLEMENTED);
		break;
	case STATUS: /* NOT IMPLEMENTED */
		DEBUG(ylog(VERB_DEBUG, "Status query received\n");)
		send_udp_error(s, from, fromlen, packet, size, ERR_NOTIMPLEMENTED);
		break;
	case NS_NOTIFY_OP: /* NOT IMPLEMENTED */
		DEBUG(ylog(VERB_DEBUG, "NS notify query received\n");)
		send_udp_error(s, from, fromlen, packet, size, ERR_NOTIMPLEMENTED);
		break;
	default: /* reserved opcodes */
		statistic_invalid_packet++;
		DEBUG(ylog(VERB_DEBUG, "Invalid or unsupported opcode\n");)
		send_udp_error(s, from, fromlen, packet, size, ERR_FORMAT);
		break;
	}
	return;
}

/* response_processor() handles the DNS response packets:
 * It decodes the name and searches for a matching entry in the
 * forwarded requests queue. If some entry matches it sends
 * the response to the original requester (the client), put
 * this record in the cache and erase the entry in the forwarded
 * requests table */
static void response_processor(byte *packet, unsigned int size, struct sockaddr *from, socklen_t fromlen)
{
	HEADER *hdr = (HEADER*) packet;
	int id = ntohs(hdr->id), retval;
	u_int16_t qtype, qclass, qdcount = ntohs(hdr->qdcount);
	struct forwardentry *p;
	char *name = NULL;
	byte *data = packet+sizeof(HEADER);
	int data_size = size-sizeof(HEADER);
	unsigned int index;
	ARG_UNUSED(fromlen);

	if (!opt_forward)
		return;

	DEBUG(ylog(VERB_DEBUG, "Response received ID: %d\n", id);)

	/* the shortest name `.' is 1 byte, + 4 for qtype/qclass = 5 bytes */
	if (qdcount < 1 || data_size < 5)
		goto invalid;

	/* decode the name */
	retval = name_decode(data, data_size, packet, &name, 1);
	if (name == NULL)  {
		if (retval == YK_INVALID)
			goto invalid;
		/* ...else out of memory */
		return;
	}

	updatep(retval);

	/* there is space for qtype and qclass? */
	if (data_size < 4)
		goto invalid;
	qtype = (data[0] << 8) | data[1];
	qclass = (data[2] << 8) | data[3];
	updatep(4);

	ylog(VERB_LOW, "%s,%d name server replied (%s %s %s ID:%d)\n",
		inet_ntoa(((struct sockaddr_in*)from)->sin_addr),
		ntohs(((struct sockaddr_in*)from)->sin_port),
		qtype_to_str(qtype), qclass_to_str(qclass), name, id);

	/* saerch in the forward table */
	p = forward_search(id, qtype, qclass, name, &index);
	if (p != NULL) {
		DEBUG(ylog(VERB_DEBUG, "Previous response matches [%s %s %s]\n",
			p->name,
			qtype_to_str(p->qtype),
			qclass_to_str(p->qclass));)
		/* cache the response */
		if (opt_cache) {
			/* don't add already cached responses:
			 * This can happenes for example when the
			 * resolver asks for the same RR two times
			 * (since the name server used a log time
			 * to response). So the same query is repeted
			 * in the forward entry list, and it will
			 * be cached two (or more) times if we don't
			 * check for this condition. */
			if (!cache_search_entry(p->name, p->qclass, p->qtype)) {
				cache_add_entry(p, packet, size);
				ylog(VERB_HIG, "Previous response cached\n");
			} else {
				DEBUG(ylog(VERB_DEBUG, "Already in cache\n");)
			}
		}
		/* send the response to the client */
		free(name);
		hdr->id = htons(p->orig_id);
		send_udp(s, packet, size, (struct sockaddr*)&p->clientaddr,
			sizeof(p->clientaddr));
		forward_free_by_index(index);
		if (forward_count > 0)
			forward_count--;
		DEBUG(ylog(VERB_DEBUG, "Response sent to client\n");)
		return;
	}
	DEBUG(ylog(VERB_DEBUG, "Response doesn't match\n");)
	free(name);
	return;

invalid:
	if(name) free(name);
	statistic_invalid_packet++;
	DEBUG(ylog(VERB_DEBUG, "Response is an invalid DNS packet\n");)
}

/* count the number of occurrences of the char 'c' in the string 's' */
size_t strcount(char *s, int c)
{
	size_t count = 0;

	while(*s) {
		if (*s++ == c)
			count++;
	}
	return count;
}

/* query_processor() processes the DNS query:
 * It decodes the query and do some sanity check, so try to find
 * a matching RR in the local RRs, if any it builds the response header
 * and call add_rr() function for any RR, and send the response to the
 * client. If there aren't matching RRs in the local RRs list then:
 * It searches in the cache, if the cache match it sends the response,
 * otherwise forwards the request to the external DNS server and creates
 * a new forwarded request entry. */
static void query_processor(byte *packet, unsigned int size, struct sockaddr *from, socklen_t fromlen)
{
	HEADER *hdr = (HEADER*) packet;
	struct sockaddr_in *in = (struct sockaddr_in *) from;
	byte *data = packet + sizeof(HEADER);
	int query_count = ntohs(hdr->qdcount);
	char *name = NULL;
	int data_size = size - sizeof(HEADER);
	byte *response = NULL;
	int response_size;
	int query_size = 0;
	int retval, qclass, qtype;
	char straddr[64];

	/* No entries in query section? */
	if (query_count == 0)
		goto invalid;

	/* Log a warning if the incoming DNS packet is truncated */
	DEBUG(if (hdr->tc) ylog(VERB_DEBUG, "Truncated packet\n");)

	/* answer only to the first query in the request */
	if (query_count > 1)
		query_count = 1;

	while (query_count--) {
		char namecopy[MAXDNAME];
		int lookups = 0;

		retval = name_decode(data, data_size, packet, &name, 1);
		if (name == NULL) {
			if (retval == YK_INVALID)
				goto invalid;
			/* ...else out of memory */
			return;
		}
		updatep(retval);
		query_size = retval+4;

		DEBUG(ylog(VERB_DEBUG, "name: %s\n", name);)

		/* Enough space for qtype and qclass? */
		if (data_size < 4)
			goto invalid;

		qtype = (data[0] << 8) | data[1];
		qclass = (data[2] << 8) | data[3];
		updatep(4);

		DEBUG(ylog(VERB_DEBUG, "(%s %s)\n",
				qtype_to_str(qtype), qclass_to_str(qclass));)
		ylog(VERB_LOW, "%s,%d asks for (%s %s %s)\n",
			inet_ntoa(((struct sockaddr_in*)from)->sin_addr),
			ntohs(((struct sockaddr_in*)from)->sin_port),
			qtype_to_str(qtype), qclass_to_str(qclass), name);

		/* AXFR requested under UDP */
		if (qtype == T_AXFR) {
			send_udp_error(s, from, fromlen, packet, size, ERR_REFUSED);
			free(name);
			return;
		}

		/* build the response using the local RRs,
		 * otherwise return NULL.
		 * build_response() returns NULL even under out-of-memory
		 * but store in response_size YK_NOMEM */

		/* Check for wildcard local RRs if the name doesn't match */
		strlcpy(namecopy, name, MAXDNAME);
		while(1) {
			int dots = strcount(namecopy, '.');
			char *p, tmpname[MAXDNAME];

			response = build_response(qclass, qtype, name, namecopy,
				packet+sizeof(HEADER), query_size,
				hdr, &response_size,
				PACKETSZ);
			lookups++;
			/* RR found? */
			if (response)
				break;
			/* Out of memory building the response? */
			if (response == NULL && response_size == YK_NOMEM) {
				free(name);
				return;
			}
			/* Name not found, retry with *.domain.com */
			/* check the number of dots first, we don't
			 * want to check for *.com, nor to do more
			 * than few lookups */
			if  (!opt_wildcard || dots < 3 || lookups > 3)
				break;
			p = strchr(namecopy, '.');
			if (!p) /* can't be true, but we make errors */
				break;
			if (p == namecopy)
				break;
			/* If the bottom level was already a wildcard,
			 * reduce of one level */
			if (p[-1] == '*') {
				p = strchr(p+1, '.');
				if (!p)
					break; /* again should be unreached */
			}
			tmpname[0] = '*';
			tmpname[1] = '\0';
			strlcat(tmpname, p, MAXDNAME);
			strlcpy(namecopy, tmpname, MAXDNAME);
		}

		/* Sent the response */
		if (response != NULL) {
			free(name);
			dns_shuffle(response, response_size);
			send_udp(s, response, response_size, from, fromlen);
			free(response);
			DEBUG(ylog(VERB_DEBUG,
				"Response sent using local RRs\n");)
			return;
		}

		/* Check the client against the FWD ACL lists */
		strlcpy(straddr, inet_ntoa(in->sin_addr), 64);
		if (acl_check_fwd(straddr) == ACL_DENY) {
			free(name);
			ylog(VERB_MED, "DNS forwarding Access denied to client %s-%d\n",
				straddr, ntohs(in->sin_port));
			send_udp_error(s, (struct sockaddr*) from,
				fromlen, packet, size, ERR_NAME);
			return;
		}

		/* If the forwarding isn't enabled send an error
		 * back to the client */
		if (opt_forward == 0) {
			free(name);
			send_udp_error(s, from, fromlen, packet, size, ERR_NAME);
			DEBUG(ylog(VERB_DEBUG, "No such RR\n");)
			return;
		} else {
			struct cacheentry *cached;

			/* Search in the cache */
			if (opt_cache) {
				HEADER *answer_hdr;

				cached = cache_search_entry(name, qclass, qtype);
				if (cached != NULL) {
					cached->hits++;
					answer_hdr = (HEADER*) cached->answer;
					answer_hdr->id = hdr->id;
					cache_shuffle(cached);
					cache_fix_ttl(cached);
					send_udp(s, cached->answer,
						cached->answer_size, from,
						fromlen);
					DEBUG(ylog(VERB_DEBUG,
						"Sent from cache\n");)
					free(name);
					return;
				}
			}
			/* Forward the request to the first external server */
			forward_request(hdr, (char*)packet, size, from, name, qtype, qclass);
			DEBUG(ylog(VERB_DEBUG, "Previous forwarded\n");)
			free(name);
			return;
		}
	}

invalid:
	statistic_invalid_packet++;
	if (name != NULL)
		free(name);
	send_udp_error(s, from, fromlen, packet, size, ERR_FORMAT);
	DEBUG(ylog(VERB_DEBUG, "Invalid DNS packet\n");)
}
