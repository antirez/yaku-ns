/* local.c
 * Local records manipulation
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
 * o The mailbox encoding standard assumes a mailbox name of the form
 *   "<local-part>@<mail-domain>".  While the syntax allowed in each of these
 *   sections varies substantially between the various mail internets, the
 *   preferred syntax for the ARPA Internet is given in [RFC-822].
 *   The DNS encodes the <local-part> as a single label, and encodes the
 *   <mail-domain> as a domain name.  The single label from the <local-part>
 *   is prefaced to the domain name from <mail-domain> to form the domain
 *   name corresponding to the mailbox.  Thus the mailbox HOSTMASTER@SRI-
 *   NIC.ARPA is mapped into the domain name HOSTMASTER.SRI-NIC.ARPA.  If the
 *   <local-part> contains dots or other special characters, its
 *   representation in a master file will require the use of backslash
 *   quoting to ensure that the domain name is properly encoded.  For
 *   example, the mailbox Action.domains@ISI.EDU would be represented as
 *   Action\.domains.ISI.EDU: TODO
 */

/* ens.h must be included before all other includes */
#include "ens.h"
#include "aht.h"

#include <string.h>
#include <stdlib.h>

/* not exported functions */

/* exported functions */
struct RRentry *alloc_rr(char *name, u_int16_t qtype, u_int16_t qclass, unsigned int size);
void local_free(void);
int local_add_entry(struct RRentry *rr);
int local_add_A(char *name, char *addr);
int local_add_CNAME(char *name, char *canonical);
int local_add_MX(char *name, char *priority, char *exchange);
int local_add_PTR(char *name, char *ptr);
int local_add_NS(char *name, char *ns);
int local_add_TXT(char *argv[]);
int local_add_SOA(int argc, char **argv);
struct RRentry *local_search(char *name, u_int16_t qtype, u_int16_t qclass,
					 u_int32_t seq);

/* global vars */
struct hashtable local_table;
u_int32_t local_ttl = TTL_LOCAL_DEFAULT;
u_int16_t local_class = C_IN;

/* -------------------------------------------------------------------------- */
void local_free(void)
{
	ht_destroy(&local_table);
}

/* Free a struct RRentry */
void ht_local_destructor(void *obj)
{
	struct RRentry *l = obj;

	free(l->data);
	free(l->name);
	free(l);
}

/* alloc_rr(): allocate and initialize elements int the local RRs table.
 * Note that the 'name' field is termined with a trailer '.' since the
 * function that decode the names add this trailer '.' we can search for
 * matching RR just with strcasecmp that is usually very optimized. */
struct RRentry *alloc_rr(char *name, u_int16_t qtype, u_int16_t qclass, unsigned int size)
{
	static u_int32_t nextid = 0;
	struct RRentry *rr;
	int l;

	rr = malloc(sizeof(struct RRentry));
	if (!rr)
		goto oom1;
	l = strlen(name);
	rr->name = malloc(l+2);
	if (!rr->name)
		goto oom2;
	memcpy(rr->name, name, l+1);
	if (!(l == 1 && name[0] == '.'))
		strcat(rr->name, ".");
	rr->qtype = qtype;
	rr->qclass = qclass;
	rr->ttl = local_ttl;
	rr->size = size;
	rr->data = malloc(rr->size);
	if (!rr->data)
		goto oom3;
	rr->next = NULL;
	rr->id = nextid++;
	return rr;

/* We can't do so match if we run out of memory adding a local RR,
 * actually ens don't allocate RRs at run-time (only at start-up)
 * so it seems not critical to exit here */
oom3:	free(rr->name);
oom2:	free(rr);
oom1:	/* return NULL; */
	perror("(allocating local RR) malloc"); exit(1);
}

/* Add the entry in the local table:
 * return -1 on error, the sequence number on success */
int local_add_entry(struct RRentry *rr)
{
	char key[HT_MAX_KEYSIZE], *k;
	u_int32_t j;
	int ret;
	size_t klen;

	/* Search the first availabe sequence number
	 * for the given Resource Record: In the local
	 * table we can have more records with the
	 * same qtype/qclass/name */
	j = 0;
	while(1) {
		unsigned int i;
		klen = rr_to_key(key, HT_MAX_KEYSIZE, rr->name, rr->qtype,
			rr->qclass, j);
		ret = ht_search(&local_table, key, &i);
		if (ret == HT_NOTFOUND)
			break;
		j++;
		continue;
	}
	if ((k = malloc(klen)) == NULL)
		goto oom;
	memcpy(k, key, klen);
	ret = ht_add(&local_table, k, rr);
	if (ret != HT_OK) {
		yakuns_assert(ret != HT_BUSY);
		/* If we run out of memory here
		 * it's better to exit, actually this
		 * code is called only at start-up. */
		goto oom;
		/* return -1; */
	}
	return j;

oom:
	ylog(VERB_FORCE, "ht_add() failed adding a local"
			"Resource Record with exit code %d\n", ret);
	exit(1);
}

void local_ylog(struct RRentry *rr)
{
	ylog(VERB_HIG, "loaded: %s %s %s\n",
		qtype_to_str(rr->qtype),
		qclass_to_str(rr->qclass),
		rr->name);
}

/* add A */
int local_add_A(char *name, char *addr)
{
	struct RRentry *rr;
	int retval;

	rr = alloc_rr(name, T_A, local_class, sizeof(struct RR_A));
	retval = inet_aton(addr,
		(struct in_addr*)&((struct RR_A*)rr->data)->addr);
	/* bad address */
	if (retval == 0) {
		ht_local_destructor(rr);
		return -1;
	}
	local_add_entry(rr);
	local_ylog(rr);
	return 0;
}

/* add MX */
int local_add_MX(char *name, char *priority, char *exchange)
{
	struct RRentry *rr;
	struct RR_MX mx;
	byte *enc_exchange;
	int enc_exchange_size;

	enc_exchange = name_encode(exchange, &enc_exchange_size, '.');
	if (enc_exchange == NULL)
		return enc_exchange_size;
	rr = alloc_rr(name, T_MX, local_class,
		sizeof(struct RR_MX)+enc_exchange_size);
	mx.preference = htons(atoi(priority));
	memcpy(rr->data, &mx, sizeof(mx));
	memcpy(rr->data+2, enc_exchange, enc_exchange_size);
	free(enc_exchange);
	local_add_entry(rr);
	local_ylog(rr);
	return 0;
}

/* add PTR */
int local_add_PTR(char *name, char *ptr)
{
	struct RRentry *rr;
	byte *enc_ptr;
	int enc_ptr_size;

	enc_ptr = name_encode(ptr, &enc_ptr_size, '.');
	if (enc_ptr == NULL)
		return enc_ptr_size;
	rr = alloc_rr(name, T_PTR, local_class, enc_ptr_size);
	memcpy(rr->data, enc_ptr, enc_ptr_size);
	free(enc_ptr);
	local_add_entry(rr);
	local_ylog(rr);
	return 0;
}

/* add CNAME */
int local_add_CNAME(char *name, char *canonical)
{
	struct RRentry *rr;
	byte *enc_cname;
	int enc_cname_size;

	enc_cname = name_encode(canonical, &enc_cname_size, '.');
	if (enc_cname == NULL)
		return enc_cname_size;
	rr = alloc_rr(name, T_CNAME, local_class, enc_cname_size);
	memcpy(rr->data, enc_cname, enc_cname_size);
	free(enc_cname);
	local_add_entry(rr);
	local_ylog(rr);
	return 0;
}

/* add NS */
int local_add_NS(char *name, char *ns)
{
	struct RRentry *rr;
	byte *enc_ns;
	int enc_ns_size;

	enc_ns = name_encode(ns, &enc_ns_size, '.');
	if (enc_ns == NULL)
		return enc_ns_size;
	rr = alloc_rr(name, T_NS, local_class, enc_ns_size);
	memcpy(rr->data, enc_ns, enc_ns_size);
	free(enc_ns);
	local_add_entry(rr);
	local_ylog(rr);
	return 0;
}

/* add TXT, XXX: fix this shit */
int local_add_TXT(char *argv[])
{
	struct RRentry *rr;
	byte *enc_txt;
	int enc_txt_size;
	char text[256];
	int j;

	text[0] = '\0';
	for (j = 2; argv[j]; j++) {
		if (j > 2)
			strlcat(text, " ", 256);
		strlcat(text, argv[j], 256);
	}
	enc_txt = name_encode(text, &enc_txt_size, '\\');
	if (enc_txt == NULL)
		return enc_txt_size;
	enc_txt_size--;
	rr = alloc_rr(argv[1], T_TXT, local_class, enc_txt_size);
	memcpy(rr->data, enc_txt, enc_txt_size);
	free(enc_txt);
	local_add_entry(rr);
	local_ylog(rr);
	return 0;
}

int local_add_SOA(int argc, char **argv)
{
	struct RRentry *rr;
	struct RR_SOA soa;
	byte *enc_dns;
	byte *enc_mailbox;
	int enc_dns_size;
	int enc_mailbox_size;
	ARG_UNUSED(argc)

	enc_dns = name_encode(argv[2], &enc_dns_size, '.');
	if (enc_dns == NULL)
		return enc_dns_size;
	enc_mailbox = name_encode(argv[3], &enc_mailbox_size, '.');
	if (enc_mailbox == NULL) {
		free(enc_dns);
		return enc_mailbox_size;
	}
	rr = alloc_rr(argv[1], T_SOA, local_class,
		sizeof(struct RR_SOA)+enc_dns_size+enc_mailbox_size);
	memcpy(rr->data, enc_dns, enc_dns_size);
	memcpy(rr->data+enc_dns_size, enc_mailbox, enc_mailbox_size);
	soa.serial = htonl(atoi(argv[4]));
	soa.refresh = htonl(atoi(argv[5]));
	soa.retry = htonl(atoi(argv[6]));
	soa.expire = htonl(atoi(argv[7]));
	soa.minimum = htonl(atoi(argv[8]));
	memcpy(rr->data+enc_dns_size+enc_mailbox_size, &soa, sizeof(soa));
	free(enc_dns);
	free(enc_mailbox);
	local_add_entry(rr);
	ylog(VERB_HIG,	"loaded: SOA for %s\n"
			"\tdns    : %s\n"
			"\tmailbox: %s\n"
			"\tserial : %lu\n"
			"\trefresh: %lu\n"
			"\tretry  : %lu\n"
			"\texpire : %lu\n"
			"\tminimum: %lu\n",
			argv[1], argv[2], argv[3],
			(unsigned long) ntohl(soa.serial),
			(unsigned long) ntohl(soa.refresh),
			(unsigned long) ntohl(soa.retry),
			(unsigned long) ntohl(soa.expire),
			(unsigned long) ntohl(soa.minimum));
	return 0;
}

/* Search in the local table */
struct RRentry *local_search(char *name, u_int16_t qtype, u_int16_t qclass, u_int32_t seq)
{
	char key[HT_MAX_KEYSIZE];
	int ret;
	unsigned int i;

	rr_to_key(key, HT_MAX_KEYSIZE, name, qtype, qclass, seq);
	ret = ht_search(&local_table, key, &i);
	if (ret == HT_FOUND)
		return (struct RRentry*) ht_value(&local_table, i);
	return NULL;
}

/* Search for a given name-class-type in the local table and put
 * all the matching RRs in the given array.
 * Four different paths for speed. */
int local_search_all(char *name, u_int16_t qtype, u_int16_t qclass, struct RRentry **rra, unsigned int size)
{
	struct RRentry *rr;
	u_int32_t seq = 0;
	int status = 0;
	unsigned int index = 0;

	yakuns_assert(rra != NULL);
	if (size == 0)
		return 0;

	/* Path for specified class and type */
	if (qtype != T_ANY && qclass != C_ANY) {
		while (size && status < 4) {
			switch(status) {
			case 0:
				rr = local_search(name, qtype, qclass, seq);
				break;
			case 1:
				rr = local_search(name, T_ANY, qclass, seq);
				break;
			case 2:
				rr = local_search(name, qtype, C_ANY, seq);
				break;
			case 3:
				rr = local_search(name, T_ANY, C_ANY, seq);
				break;
			default: yakuns_assert(1 != 1); /* unreached */
			}

			if (rr == NULL) {
				seq = 0;
				status++;
				continue;
			}

			rra[index] = rr;
			size--;
			index++;
			seq++;
		}
		return index;
	}

	/* Path for class = * and type = * */
	if (qtype == T_ANY && qclass == C_ANY) {
		int types[] = {T_A, T_NS, T_PTR, T_MX, T_TXT, T_SOA, T_ANY};
		int classes[] = {C_IN, C_ANY, C_CHAOS};
		int types_nr = sizeof(types) / sizeof(int);
		int classes_nr = sizeof(classes) / sizeof(int);
		int type, class;

		for (class = 0; class < classes_nr; class++) {
			for (type = 0; type < types_nr; type++) {
				for (seq = 0; ; seq++) {
					rr = local_search(name, types[type],
						classes[class], seq);
					if (rr == NULL)
						break;
					rra[index] = rr;
					size--;
					index++;
					if (size == 0)
						goto out1;
				}
			}
		}
out1:
		return index;
	}

	/* Path for specified class and qtype = * */
	if (qtype == T_ANY && qclass != C_ANY) {
		int types[] = {T_A, T_NS, T_PTR, T_MX, T_TXT, T_SOA, T_ANY};
		int types_nr = sizeof(types) / sizeof(int);
		int type;

		for (type = 0; type < types_nr; type++) {
			for (seq = 0; ; seq++) {
				unsigned int old_index = index;

				rr = local_search(name, types[type], qclass,
					seq);
				if (rr != NULL) {
					rra[index] = rr;
					size--;
					index++;
					if (size == 0)
						goto out2;
				}
				/* Search it with the ANY class */
				rr = local_search(name, types[type], C_ANY,
					seq);
				if (rr != NULL) {
					rra[index] = rr;
					size--;
					index++;
					if (size == 0)
						goto out2;
				}
				if (index == old_index)
					break;
			}
		}
out2:
		return index;
	}

	/* Path for specified qtype and qclass = * */
	if (qtype != T_ANY && qclass == C_ANY) {
		int classes[] = {C_IN, C_ANY, C_CHAOS};
		int classes_nr = sizeof(classes) / sizeof(int);
		int class;

		for (class = 0; class < classes_nr; class++) {
			for (seq = 0; ; seq++) {
				unsigned int old_index = index;

				rr = local_search(name, qtype, classes[class], seq);
				if (rr != NULL) {
					rra[index] = rr;
					size--;
					index++;
					if (size == 0)
						goto out3;
				}
				rr = local_search(name, T_ANY, classes[class], seq);
				if (rr != NULL) {
					rra[index] = rr;
					size--;
					index++;
					if (size == 0)
						goto out3;
				}
				if (index == old_index)
					break;
			}
		}
out3:
		return index;
	}

	yakuns_assert(1 != 1); /* unreached */
	return index;
}

void local_init(void)
{
	ht_init(&local_table);
	ht_set_hash(&local_table, ht_dnskey_hash);
	ht_set_key_destructor(&local_table, ht_destructor_free);
	ht_set_val_destructor(&local_table, ht_local_destructor);
	ht_set_key_compare(&local_table, ht_dnskey_compare);
	local_table.hashf = ht_dnskey_hash;
	local_table.key_destructor = ht_destructor_free;
	local_table.val_destructor = ht_local_destructor;
	local_table.key_compare = ht_dnskey_compare;
}
