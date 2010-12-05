/* forward.c
 * Yaku-ns forwarding code
 *
 * Copyright (C) 2000,2001,2002 by Salvatore Sanfilippo
 * <antirez@invece.org>
 *
 * This code is under the GPL license
 * See the COPYING file for more information
 *
 * STATUS
 *
 * OK:      ENS behaves as desidered
 * TODO:    ENS behaves in some different way or the
 *          feature is not supported.
 * IGNORED: ENS behaves in some different way since it
 *          is wanted.
 *
 * o Processing responses (RFC speaks about resolver, but it's general)
 *     o Check the header for rasonableness. Discard datagrams
 *       which are queries when responses are expected: OK
 *     o Parse the sections of the message, and insure that all
 *       the RRs are correctly formatted: INGORED, ENS will parse
 *       only the relevant part of the responses. It works on the
 *       respect of its security, but don't try to act as firewall
 *       proxy for the DNS protocol.
 *     o As an optional step, check the TTLs of arriving data looking
 *       for RRs with excessively long TTLs. If a RR has an accessively
 *       long TTL, say greater than 1 week, either discard the whole
 *       response, or limit all TTLs to 1 week: IGNORED, ENS does not
 *       set this kind of limits, its internal design does not relay
 *       on the TTL value to avoid floods (since it discard old data
 *       to insert new data when there isn't more space left).
 *       Also we cache the DNS reply using the shortest TTL from the RRs TTL,
 *       with a max and min barrier.
 * o Response matching:
 *     o Don't expect that the response come from the same IP address
 *       than the one used sending the query to the nameserver: OK
 *       Spoofing UDP is already trivial, so whe don't lost nothing here.
 *     o If the resolver retrasmit a particular request to a name
 *       server it SHOULD be able to use a response from any of the
 *       retrasmission: OK
 *     o A name server will occasionally not have a current copy of a
 *       zone which it should have according to some NS RRs.  The
 *       resolver should simply remove the name server from the current
 *       SLIST, and continue: TODO
 */

/* ens.h must be included before all other includes */
#include "ens.h"
#include "aht.h"

#include <string.h>
#include <stdlib.h>

/* global vars */
struct in_addr forward_server[MAX_FORWARD_SERVERS];
int forward_server_count = 0;	/* how many forward servers */
int forward_count = 0;		/* number of pending forwarded requests */
int forward_max = FORWARD_MAX_QUEUE;
int forward_timeout = FORWARD_TIMEOUT;
int dns_forward_port = DNS_FORWARD_PORT;
struct hashtable forward_table;

/* not exported functions */
static void forward_free_oldest(void);

/* exported functions */
void forward_request(HEADER *hdr, char *packet, unsigned int size, struct sockaddr *from, char *name, u_int16_t qtype, u_int16_t qclass);
void forward_free_expired(void);
struct forwardentry *forward_search(int id, int qtype, int qclass, char *name, unsigned int *index);

/* -------------------------------------------------------------------------- */

/* The destructor for the forward entry */
void ht_forward_destructor(void *obj)
{
	struct forwardentry *forward = obj;

	free(forward->name);
	free(forward->query_packet);
	free(forward);
}

/* Compare two keys */
int ht_forward_compare(void *key1, void *key2)
{
	u_int16_t k1l, k2l;

	memcpy(&k1l, key1, 2);
	memcpy(&k2l, key2, 2);
	if (k1l != k2l)
		return 0; /* keys of different length can't match */
	return !memcmp(key1, key2, k1l);
}

/* Create a new entry in the forward table */
struct forwardentry *forward_add_entry(char *name, u_int16_t qtype,
				       u_int16_t qclass, u_int16_t id)
{
	struct forwardentry *forward;
	char key[HT_MAX_KEYSIZE], *k;
	int ret;
	size_t klen;

	/* If the forward queue is full the oldest entry
	 * is removed. XXX: better strategy? Think about DoS
	 * and performance. */
	if (forward_count >= forward_max)
		forward_free_oldest();
	if ((forward = malloc(sizeof(struct forwardentry))) == NULL)
		goto oom1;
	if ((forward->name = strdup(name)) == NULL)
		goto oom2;
	forward->qtype = qtype;
	forward->qclass = qclass;
	forward->id = id;
	klen = rr_to_key(key, HT_MAX_KEYSIZE, name, qtype, qclass, id);
	if ((k = malloc(klen)) == NULL)
		goto oom3;
	memcpy(k, key, klen);
	ret = ht_add(&forward_table, k, forward);
	if (ret != HT_OK)
		goto oom3;
	return forward;

oom3:	free(forward->name);
oom2:	free(forward);
oom1:	return NULL;
}

void forward_request(HEADER *hdr, char *packet, unsigned int size, struct sockaddr *from, char *name, u_int16_t qtype, u_int16_t qclass)
{
	struct sockaddr_in forward_addr;
	struct forwardentry *f;
	u_int16_t forward_id = get_rand_id();

	/* Create the entry in the forward hash table:
	 * if we run out of memory here filling the rest
	 * of the structure we don't need to remove the
	 * entry from the hash table, since it will expire
	 * very soon (usually at max in one second), see below */
	f = forward_add_entry(name, qtype, qclass, forward_id);
	if (f == NULL) /* Out of memory, do nothing */
		return;
	f->server_number = 0;
	f->orig_id = ntohs(hdr->id);
	hdr->id = htons(forward_id);
	f->timestamp = get_sec();
	f->clientaddr.sin_family = AF_INET;
	f->clientaddr.sin_addr.s_addr =
		((struct sockaddr_in*)from)->sin_addr.s_addr;
	f->clientaddr.sin_port = ((struct sockaddr_in*)from)->sin_port;
	/* save the query if we have more than one forwarder */
	if (forward_server_count > 1) {
		f->query_packet = malloc(size);
		if (f->query_packet == NULL)
			goto oom1;
		memcpy(f->query_packet, packet,size);
		f->query_size = size;
	} else {
		f->query_packet = NULL;
		f->query_size = 0; /* useless */
	}
	forward_addr.sin_family = AF_INET;
	forward_addr.sin_port = htons(dns_forward_port);
	forward_addr.sin_addr.s_addr = forward_server[0].s_addr;
	send_udp(s, packet, size, (struct sockaddr*) &forward_addr, sizeof(forward_addr));
	forward_count++;
	return;

oom1:
	/* if we run out of memory the timestamp is set to zero will ensure
	 * that the entry will expire ASAP, the other fileds are set to
	 * some clear value */
	f->timestamp = 0;
	f->query_packet = NULL;
	f->query_size = 0;
	return;
}

/* Free expired entry and resend timed out query to the next server */
void forward_free_expired(void)
{
	unsigned int index = 0;
	int ret;
	struct forwardentry *f;
	time_t now = get_sec();

	if (forward_table.used == 0)
		return;

	/* search and remove expired entries */
	while ((ret = ht_get_byindex(&forward_table, index)) != -1) {
		if (ret == 0) {
			index++;
			continue;
		}
		f = ht_value(&forward_table, index);
		if (now - f->timestamp > forward_timeout) {
			log(VERB_HIG, "Expired forwarded request %s %s %s, "
					"ID:%d\n",
					qtype_to_str(f->qtype),
					qclass_to_str(f->qclass),
					f->name, f->id);
			ht_free(&forward_table, index);
			forward_count--;
		} else if (forward_server_count > 1 &&
			   f->server_number < (forward_server_count-1) &&
			   now - f->timestamp > (next_server_timeout * (f->server_number+1)))
		{
			struct sockaddr_in forward_addr;

			f->server_number++;
			forward_addr.sin_family = AF_INET;
			forward_addr.sin_port = htons(dns_forward_port);
			forward_addr.sin_addr.s_addr =
				forward_server[f->server_number].s_addr;
			DEBUG(log(VERB_FORCE, "ASK TO SERVER %d [%s %s %s]\n",
						f->server_number,
						qtype_to_str(f->qtype),
						qclass_to_str(f->qclass),
						f->name);)
			send_udp(s, f->query_packet,
					f->query_size,
					(struct sockaddr*) &forward_addr,
					sizeof(forward_addr));
		}
		index++;
	}
}

static void forward_free_oldest(void)
{
	unsigned int index = 0, oldest_index = 0;
	int ret;
	struct forwardentry *f, *oldest = NULL;

	/* XXX: better to remove a random entry? at least much faster */
	while ((ret = ht_get_byindex(&forward_table, index)) != -1) {
		if (ret == 0) {
			index++;
			continue;
		}
		f = ht_value(&forward_table, index);
		if (oldest == NULL || f->timestamp < oldest->timestamp) {
			oldest = f;
			oldest_index = index;
		}
		index++;
	}
	if (oldest) {
		ht_free(&forward_table, oldest_index);
		forward_count--;
	}
	return;
}

/* search a matching entry in the forward table,
 * store the entry index in the *index (if not NULL) to make
 * the live easier to the caller that want to free it */
struct forwardentry *forward_search(int id, int qtype, int qclass, char *name,
				    unsigned int *index)
{
	char key[HT_MAX_KEYSIZE];
	int ret;
	unsigned int i;

	rr_to_key(key, HT_MAX_KEYSIZE, name, qtype, qclass, id);
	ret = ht_search(&forward_table, key, &i);
	if (ret == HT_FOUND) {
		if (index) *index = i;
		return (struct forwardentry *) forward_table.table[i]->data;
	}
	return NULL;
}

void forward_free_by_index(unsigned int index)
{
	ht_free(&forward_table, index);
}

void forward_init(void)
{
	ht_init(&forward_table);
	ht_set_hash(&forward_table, ht_dnskey_hash);
	ht_set_key_destructor(&forward_table, ht_destructor_free);
	ht_set_val_destructor(&forward_table, ht_forward_destructor);
	ht_set_key_compare(&forward_table, ht_dnskey_compare);
}
