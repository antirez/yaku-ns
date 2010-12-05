/* afxr_out.c
 * Zone transfer implementation (Output)
 * and DNS over TCP only for AXFR.
 *
 * Copyright (C) 2000,2001,2002 by Salvatore Sanfilippo
 * <antirez@invece.org>
 *
 * This code is under the GPL license
 * See the COPYING file for more information
 */

/* STATUS
 *
 * OK:      behaves as desidered
 * TODO:    behaves in some different way or the
 *          feature is not supported.
 * IGNORED: behaves in some different way since it
 *          is wanted.
 *
 * axfr-clarity draft:
 * o Support for zone trasfer over TCP: OK
 * o If the master server can't provide a zone transfer send an error: TODO
 *   for now it closes the TCP connection.
 * o Master MAY send multiple answers per message, up to 65535 bytes: OK
 * o Masters that support multiple RRs in the same message SHOULD be
 *   configurable to send one RR for message: OK
 * o If the zone transefer does not fit in 65535 bytes the master MUST send
 *   more messages: OK
 * o SHOULD compress the names in the zone transfer: IGNORED
 * o The header of the message MUST be the following:
 *     ID      Copy from request: OK
 *     QR      1: OK
 *     OPCODE  QUERY: OK
 *     AA      1 (but MAY be 0 when RCODE is nonzero): OK
 *     TC      0: OK
 *     RD      Copy from request: OK
 *     RA      Set according to availability of recursion: OK
 *     Z       000: OK
 *     RCODE   0 or error code: TODO, now the error isn't sent.
 * o No additional section processing: OK
 * o The question section SHOULD be the same as the request one
 *   for the first message: OK
 * o Subsequent messages SHOULD NOT have a question section: OK
 * o The master server MUST send messages with an empty authority
 *   section: OK.
 * o The first and latest RR transimtted MUST be the SOA record
 *   for the zone: OK
 * o The initial and final SOA records MUST be tha same: OK
 * o The transfer order of all the other RRs in the zone is undefinied: OK
 *
 * RFC1034:
 * o If the server needs to close a dormant connection to reclaim resource
 *   it SHOULD wait until the connection has been idle for a period on
 *   the order of two minutes: OK
 *
 * RFC1035:
 * o Zone refresh and reload processing:
 *     o If a master is sending a zone out via AXFR, and a new
 *       version is created during the transfer, the master SHOULD
 *       continue to send the old version. In any case, it SHOULD
 *       never send part of one version and part of the others: OK
 */

/* ens.h must be included before all other includes */
#include "ens.h"
#include "aht.h"

#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/wait.h>

#define AXFR_CLIENT_MAX		50
#define AXFR_CLIENT_TIMEOUT	120	/* At least 2 min, see RFC1034 */
#define TCP_REQS_DEFAULT	2	/* SOA + AXFR */

/* global vars */
int opt_axfr = 0;
int opt_axfr_compatmode = 1;
int opt_tcp_requests_for_connection = TCP_REQS_DEFAULT;
int opt_tcp_port = DNS_PORT;	/* Default is port 53, override it with -P */
int tcp_s;			/* the TCP socket */

/* local vars */
static volatile int axfr_clients = 0; /* current number of clients */

/* not exported functions */
static void send_zone(HEADER *hdr, char *query, int querysize, char *zone,
							int clientsocket);

static void send_soa(HEADER *hdr, char *query, int querysize, char *zone,
							int clientsocket);
static int match_zone(char *name, char *zone);
static struct RRentry *search_soa(char *zone);
static void axfr_sigchld(int sid);

/* exported functions */
int axfr_init(void);
void tcp_handler(void);

/* -------------------------------------------------------------------------- */

/* Initialize the AXFR capability */
int axfr_init(void)
{
	struct sockaddr_in sa;
	int on = 1;

	tcp_s = socket(AF_INET, SOCK_STREAM, 0);
	if (tcp_s == -1) {
		perror("[axfr_init] socket");
		return -1;
	}

	if (setsockopt(tcp_s, SOL_SOCKET, SO_REUSEADDR, &on,
		sizeof(on)) == -1) {
		perror("[axfr_init] warning: setsockopt(SO_REUSEADDR)");
	}

        /* fill the address structure */
	sa.sin_family = AF_INET;
	sa.sin_port = htons(opt_tcp_port);
	if (!opt_bindaddr) {
		sa.sin_addr.s_addr = htonl(INADDR_ANY); /* all interfaces */
	} else {
		struct in_addr tmp;
		if (inet_aton(bindaddr, &tmp) == 0) {
			ylog(VERB_FORCE, "[axfr_init] bad IP address "
					"for binding\n");
			exit(1);
		}
		sa.sin_addr.s_addr = tmp.s_addr;
	}

	/* bind the socket */
	if (bind(tcp_s, (struct sockaddr*) &sa, sizeof(sa)) == -1) {
		perror("[axfr_init] bind");
		close(tcp_s);
		return -1;
	}

	if (listen(tcp_s, 5) == -1) {
		perror("[axfr_init] listen");
		close(tcp_s);
		return -1;
	}
	Signal(SIGCHLD, axfr_sigchld);
	signal_block(SIGCHLD);
	return 0;
}

/* Handle the SIGCHLD, taking the count of the clients connected */
static void axfr_sigchld(int sid)
{
	pid_t pid;
	int stat;
	ARG_UNUSED(sid)

	while ((pid = waitpid(-1, &stat, WNOHANG)) > 0) {
		axfr_clients--;
	}
	yakuns_assert(axfr_clients >= 0);
	return;
}

/* Called on timeout */
static void axfr_timeout(int sid)
{
	ARG_UNUSED(sid);

	exit(0); /* kill the process */
}

/* Handle a new TCP connection -- this DNS server uses the DNS over TCP
 * only for the zone transfer */
void tcp_handler(void)
{
	HEADER *hdr;
	byte tmp[2];
	char request[512];	/* even under TCP we limit to 512 bytes */
	byte *data;		/* points after the DNS header */
	int data_size;		/* data size left */
	socklen_t addrlen;
        int new;                /* new socket fd */
	int query_count;	/* question sections in the query */
	unsigned int size;	/* query size */
	int retval, n_read;
	u_int16_t qtype, qclass;
	char *name = NULL;
	char straddr[64];	/* string converted IP address */
	pid_t childpid;
	struct sockaddr_in newsa;

	/* accept the connection */
	addrlen = sizeof(newsa);
	/* Allow SIGCHLD delivery only here, to avoid counter inc/dec races */
	// XXX: signal block/unblock moved to the core() function.
	//signal_unblock(SIGCHLD);
	/* accept can't block here, since we are here by select(2) */
	new = accept(tcp_s, (struct sockaddr*) &newsa, &addrlen);
	//signal_block(SIGCHLD);
	if (new == -1) {
		perror("[tcp_handler] accept");
		goto out;
	}
	strlcpy(straddr, inet_ntoa(newsa.sin_addr), 64);

	/* Check the ACL */
	if (acl_check_axfr(straddr) == ACL_DENY) {
		ylog(VERB_MED, "AXFR: access denied to client %s-%d\n",
			straddr, ntohs(newsa.sin_port));
		goto out;
	}

	/* Max number of clients reached? */
	if (axfr_clients >= AXFR_CLIENT_MAX) {
		ylog(VERB_MED, "AXFR: too many AXFR clients, "
			      "access denied to %s-%d\n",
			straddr, ntohs(newsa.sin_port));
		goto out;
	}

	/* The client's IP isn't denied, so we can fork */
	axfr_clients++;
	if ((childpid = fork()) == -1) {
		axfr_clients--;
		perror("[tcp_handler] fork");
		goto out;
	}

	if (childpid == 0) {
		int left_requests = opt_tcp_requests_for_connection;
		
		Signal(SIGALRM, axfr_timeout);
		alarm(AXFR_CLIENT_TIMEOUT);	/* set the timeout */

		while(left_requests-- ||
		      (opt_tcp_requests_for_connection == 0))
		{
			n_read = recv(new, tmp, 2, 0); /* read the query size */
			if (n_read != 2)
				goto child_out;
			size = (tmp[0] << 8) | tmp[1]; /* endianess conv. */
			if (size > 512)
				goto child_out;

			/* read the request */
			n_read = recv(new, request, size, 0);
			if (n_read <= 0 || (unsigned)n_read != size)
				goto child_out;

			/* SANITY CHECKS:
			 * packet too short
			 * accept only standard query
			 * accept only one query section
			 * valid name
			 * enough space for qtype/class
			 */
			hdr = (HEADER*) request;
			if (size < sizeof(HEADER) ||
			hdr->qr == 1 ||
			hdr->opcode != 0)
				goto child_out;
			data_size = size;
			data = (unsigned char*)request + sizeof(HEADER);
			query_count = ntohs(hdr->qdcount);
			if (query_count != 1)
				goto child_out;

			/* parse the query */
			retval = name_decode(data, data_size,
                                        (unsigned char*)request, &name, 1);
			if (name == NULL)
				goto child_out;
			updatep(retval);
			if (data_size < 4)
				goto child_out;
			qtype =  (data[0] << 8) | data[1];
			qclass = (data[2] << 8) | data[3];
			updatep(4);

			/* The only two accepted requests under TCP are
			 * IN/AXFR and IN/SOA */
			if (qclass == C_IN && qtype == T_AXFR) {
				ylog(VERB_LOW, "AXFR requested for (%s) from "
					"%s-%d\n", name, straddr,
					ntohs(newsa.sin_port));
				send_zone(hdr, request+sizeof(HEADER), retval+4,
						name, new);
			} else if (qclass == C_IN && qtype == T_SOA) {
				ylog(VERB_MED, "TCP IN SOA requested for (%s) from "
					"%s-%d\n", name, straddr,
					ntohs(newsa.sin_port));
				send_soa(hdr, request+sizeof(HEADER), retval+4,
						name, new);
			} else {
				ylog(VERB_MED, "TCP unaccepted request (%s %s) "
						"from %s-%d\n",
						qclass_to_str(qclass),
						qtype_to_str(qtype),
						straddr,
						ntohs(newsa.sin_port));
				goto child_out;
			}
			free(name);
			name = NULL;
		}
child_out:
		free(name);
		exit(1);
	}

out:
	if (new != -1)
		close(new);
	return;
}

/* Send the AXFR reply under TCP */
static void send_zone(HEADER *hdr, char *query, int querysize, char *zone, int clientsocket)
{
	int size = 0, retval;
	byte *response = NULL, *tmp;
	struct RRentry *rr, *soa;

	retval = build_header(&response, hdr, 1);
	if (retval == YK_NOMEM)
		goto oom;
	size += retval;
	/* Add the question section:
	 * Only the first message contains this section */
	if ((tmp = realloc(response, size+querysize)) == NULL)
		goto oom;
	response = tmp;
	memcpy(response+size, query, querysize);
	size += querysize;
	/* Lookup the SOA RR */
	soa = search_soa(zone);
	if (soa) {
		unsigned int index = 0;
		int ret;

		/* The first RR is the SOA */
		retval = add_rr(&response, hdr, soa, size, AN_SECTION, 0);
		if (retval == YK_NOMEM)
			goto oom;
		size += retval;
		/* If compatibility mode is enabled send the first
		 * message with the SOA RR */
		if (opt_axfr_compatmode)
			goto sendit;
		while ((ret = ht_get_byindex(&local_table, index)) != -1) {
			index++;
			if (ret == 0)
				continue;
			rr = ht_value(&local_table, index);
			if (rr->qtype == T_SOA || !match_zone(rr->name, zone))
				continue;
			/* Add this RR */
			retval = add_rr(&response, hdr, rr, size, AN_SECTION, 0);
			if (retval == YK_NOMEM)
				goto oom;
			size += retval;
sendit:
			/* Send the message if reaches 60000 bytes:
			 * we are assuming that a single RR can't be
			 * more than 5535 bytes. */
			if (opt_axfr_compatmode || size >= 60000) {
				HEADER *newhdr;
				send_tcp(response, size, clientsocket);
				free(response);
				response = NULL;
				size = 0;
				size += build_header(&response, hdr, 1);
				newhdr = (HEADER*) response;
				newhdr->qdcount = 0;
			}
		}
		/* The last RR is the SOA */
		retval = add_rr(&response, hdr, soa, size, AN_SECTION, 0);
		if (retval == YK_NOMEM)
			goto oom;
		size += retval;
	}
	send_tcp(response, size, clientsocket);
	free(response);
	return;

oom:	/* We can't do much better than this here */
	free(response);
	perror("[send_zone] allocating memory");
	exit(1);
}

/* Send the SOA reply under TCP */
static void send_soa(HEADER *hdr, char *query, int querysize, char *zone, int clientsocket)
{
	int size = 0, retval;
	byte *response = NULL, *tmp;
	struct RRentry *soa;

	retval = build_header(&response, hdr, 1);
	if (retval == YK_NOMEM)
		goto oom;
	size += retval;
	/* Add the question section:
	 * Only the first message contains this section */
	if ((tmp = realloc(response, size+querysize)) == NULL)
		goto oom;
	response = tmp;
	memcpy(response+size, query, querysize);
	size += querysize;
	/* Lookup the SOA RR */
	soa = search_soa(zone);
	if (soa) {
		retval = add_rr(&response, hdr, soa, size, AN_SECTION, 0);
		if (retval == YK_NOMEM)
			goto oom;
		size += retval;
	}
	send_tcp(response, size, clientsocket);
	free(response);
	return;

oom:	/* We can't do much better than this here */
	free(response);
	perror("[send_soa] allocating memory");
	exit(1);
}

/* Look for the SOA record for the given zone */
static struct RRentry *search_soa(char *zone)
{
	return local_search(zone, T_SOA, C_IN, 0);
}

/* Check if a name matches a zone */
static int match_zone(char *name, char *zone)
{
	if (strlen(name) < strlen(zone))
		return 0;
	if (strlen(name) == strlen(zone))
		return !strcmp(name, zone);
	if (!strcasecmp(name+strlen(name)-strlen(zone), zone) &&
	    *(name+strlen(name)-strlen(zone)-1) == '.')
		return 1;
	return 0;
}
