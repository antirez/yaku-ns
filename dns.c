/* dns.c
 * DNS protocol library
 *
 * Copyright (C) 2000,2001,2002 by Salvatore Sanfilippo
 * <antirez@invece.org>
 *
 * This code is under the GPL license
 * See the COPYING file for more information
 *
 *
 * STATUS
 *
 * OK:      ENS behaves as desidered
 * TODO:    ENS behaves in some different way or the
 *          feature is not supported.
 * IGNORED: ENS behaves in some different way since it
 *          is wanted.
 *
 * RFC 1035:
 * o Data trasmission order: OK
 * o Comparisons MUST be done in case insensitive: OK
 * o Case should be preserved internally: OK
 * o Size limits:
 *   labels 63 octects: OK
 *   names 255 octects: IGNORED, ens handles longer names.
 *   TTL unsigned 32-bit: OK
 *   UDP messages 512 bytes: OK
 * o Comparisons MUST be done assuming ASCII with zero
 *   parity: TODO and to check, ens just uses strcasecmp().
 * o ENS name decompression seems to follow the RFC, but
 *   a max of 64 nested labels are allowed, to prevent DoS.
 * o UDP messages longer than 512 bits are truncated and
 *   the TC bit is set: OK
 * o Nameserver MUST not stop to answer to UDP queries
 *   while it waits for TCP data: OK
 * o Nameserver SHOULD not delay requests while it reloads
 *   a zone from master files or while it incorporate a
 *   newly refreshed zone into it's database: TODO or to IGNORE.
 * o Time:
 *     o All timers are 32bit integers: OK
 *     o TTLs of Zone RRs are costant: OK
 * o Standard query processing:
 *     o When processing queries with QCLASS=ANY the response
 *       SHOULD never be authoritative unless the server can
 *       guarantee that the response covers all the classes: TODO
 *     o When composing new respnse, RRs wich should be putted
 *       in the additional section but are already present in the
 *       answer or authority section may be omitted: IGNORED
 *     o When a response is so long that truncation is required
 *       the truncation SHOULD start at the end of the repsonse
 *       and work forward in the datagram: TODO
 *     o The MINIMUM value in the SOA should be used to set a
 *       floor on the TTL of the data distributed from a zone: TODO
 *     o This floor function SHOULD be done when the data is copied
 *       into a response: TODO
 * o Inverse queries are NOT suppoted.
 */

/* ens.h must be included before all other includes */
#include "ens.h"

#include <string.h>
#include <stdlib.h>

#define MAX_RR 256

/* non exported functions */
static byte *get_qsection(byte *packet, unsigned int size, int *qsize);

/* exported functions */
int add_rr(byte **dest, HEADER *hdr, struct RRentry *rr, unsigned int size, int section, int maxsize);
int build_header(byte **dest, HEADER *hdr, int aa);
u_int32_t get_min_ttl(byte *packet, unsigned int packet_size);
void dns_shuffle(byte *packet, unsigned int packet_size);
int send_udp(int fd, void *packet, unsigned int size, struct sockaddr *to, int tolen);
int send_tcp(byte *packet, int len, int sd);
void send_udp_error(int fd, struct sockaddr *from, int fromlen, byte *packet, unsigned int size, int error_type);
byte *build_error(int *retsize, byte *packet, unsigned int size, int error_type);
int name_decode(byte *ptr, int data_size, byte *base, char **name, int compr);
byte *name_encode(char *msg, int *size, char sep);

/* -------------------------------------------------------------------------- */
/* Add a Resource Record to the DNS packet:
 * return codes:
 * >= 0 	success
 * YK_NOMEM	out of memory */
int add_rr(byte **dest, HEADER *hdr, struct RRentry *rr, unsigned int size, int section, int maxsize)
{
	int offset = size, retval, newsize;
	u_int16_t tmp16;
	u_int32_t tmp32;
	byte *encoded_name, *tmp;
	ARG_UNUSED(hdr)

#if 0
	printf("Add %s %s %s (%d)\n", rr->name, qclass_to_str(rr->qclass),
					   qtype_to_str(rr->qtype), size);
#endif

	encoded_name = name_encode(rr->name, &retval, '.');
	if (retval < 0) { /* Out of memory or invalid name */
		switch(retval) {
		case YK_NOMEM:
			return YK_NOMEM;
			break;
		case YK_INVALID:
		default:
			/* just skip it */
			return 0;
			break;
		}
	}

	/* The new size of the packet */
	newsize = size + retval + RRFIXEDSZ + rr->size;

	/* Check if there is enough space */
	if (newsize > maxsize) {
		/* For additional sections just don't add the RR */
		switch(section) {
		case NS_SECTION:
		case AR_SECTION:
			return 0;
		}
	}

	/* Allocate the memmory needed */
	if ((tmp = realloc(*dest, newsize)) == NULL)
		return YK_NOMEM;
	*dest = tmp;

	/* add the name */
	memcpy((*dest)+offset, encoded_name, retval);
	offset += retval;
	free(encoded_name);

	/* add qtype, qclass, ttl, rdlen and the rr */
	tmp16 = htons(rr->qtype);
	memcpy((*dest)+offset, &tmp16, 2);
	offset += 2;
	tmp16 = htons(rr->qclass);
	memcpy((*dest)+offset, &tmp16, 2);
	offset += 2;
	tmp32 = htonl(rr->ttl);
	memcpy((*dest)+offset, &tmp32, 4);
	offset += 4;
	tmp16 = htons(rr->size);
	memcpy((*dest)+offset, &tmp16, 2);
	offset += 2;
	memcpy((*dest)+offset, rr->data, rr->size);
	offset += rr->size;

	switch(section) {
	case QD_SECTION:
		((HEADER*)*dest)->qdcount =
			htons(ntohs(((HEADER*)*dest)->qdcount)+1);
		break;
	case AN_SECTION:
		((HEADER*)*dest)->ancount =
			htons(ntohs(((HEADER*)*dest)->ancount)+1);
		break;
	case NS_SECTION:
		((HEADER*)*dest)->nscount =
			htons(ntohs(((HEADER*)*dest)->nscount)+1);
		break;
	case AR_SECTION:
		((HEADER*)*dest)->arcount =
			htons(ntohs(((HEADER*)*dest)->arcount)+1);
		break;
	default:
		yakuns_assert(0 == 1); /* unreached */
		break;
	}
	return offset - size;
}

/* Build an usual DNS packet header:
 *
 * return sizeof(HEADER) on success
 * YK_NOMEM if runs out of memory */
int build_header(byte **dest, HEADER *hdr, int aa)
{
	HEADER *tmp;

	tmp = malloc(sizeof(HEADER));
	if (tmp == NULL) /* out of memory */
		return YK_NOMEM;

	memset(tmp, 0, sizeof(HEADER));
	tmp->id = hdr->id;
	tmp->qr = 1;
	tmp->opcode = 0;
	tmp->aa = aa;
	tmp->tc = 0;
	tmp->rd = hdr->rd;
	tmp->ra = 1;
	tmp->unused = 0;
	tmp->rcode = ERR_SUCCESSFUL;
	tmp->qdcount = htons(1);
	tmp->ancount = 0;
	tmp->nscount = 0;
	tmp->arcount = 0;

	*dest = (byte*) tmp;
	return sizeof(HEADER);
}

/* This function fixes the RRs's TTL field in the given packets
 * accordly to the current time */
void fix_ttl(byte *packet, unsigned int packet_size, time_t last_fix, time_t now)
{
	HEADER *hdr = (HEADER*) packet;
	int query_count = ntohs(hdr->qdcount);
	byte *data = packet + sizeof(HEADER);
	int data_size = packet_size - sizeof(HEADER);
	int retval, rdata;
	u_int32_t ttl, r_ttl, tmp32;
	u_int32_t diff = (u_int32_t) now - last_fix;

	/* packet_size should contain at least the header */
	if (packet_size < sizeof(HEADER))
		return;

	/* Dont accept packets with multiple queries */
	if (query_count != 1)
		return;

	/* Skip the Question Section */
	while(query_count--) {
		/* SANITY CHECK: 5 is the name '.' + qtype and qclass */
		if (data_size < 5)
			return;
		retval = name_decode(data, data_size, packet, NULL, 1);
		if (retval < 0) /* invalid name format */
			return;
		updatep(retval);
		if (data_size < 4) /* enough space for qtype and qclass? */
			return;
		updatep(4);
	}

	/* Fix the TTLs */
	while(data_size >= RRFIXEDSZ) {
		/* skip the name */
		retval = name_decode(data, data_size, packet, NULL, 1);
		if (retval < 0) /* invalid name format */
			return;
		updatep(retval);

		/* enough space for class, type, ttl, rrsize ? */
		if (data_size < 2+2+4+2)
			return;

		/* skip the dns class and type of the RR */
		updatep(4);

		/* finally we can read the TTL value, with any alignment */
		memcpy(&tmp32, data, 4);
		r_ttl = ntohl(tmp32);

		/* Fix it */
		if (r_ttl > diff)
			r_ttl -= diff;
		else
			r_ttl = 0;

		/* store the fixed TTL */
		ttl = htonl(r_ttl);
		memcpy(data, &ttl, 4);

		/* skip the TTL field */
		updatep(4);

		/* get the RR data size */
		rdata = (data[0] << 8) | data[1];
		updatep(2);

		/* skip the RR data size */
		if (data_size < rdata)
			return;
		updatep(rdata);
		if (data_size == 0)
			break;
	}
}

/* function related to dns.c but used only in caching.
 * This function gets the MIN ttl of all the Resource Records
 * that the DNS packet contains.
 * For malformed and truncated packets the TTL is 0 */
u_int32_t get_min_ttl(byte *packet, unsigned int packet_size)
{
	HEADER *hdr = (HEADER*) packet;
	int query_count = ntohs(hdr->qdcount);
	byte *data = packet + sizeof(HEADER);
	int data_size = packet_size - sizeof(HEADER);
	int retval, rdata;
	u_int32_t ttl = 0xffffffff, r_ttl, tmp32;

	/* packet_size should contain at least the header */
	if (packet_size < sizeof(HEADER))
		return 0;

	/* TTL for responses that contains errors are fixed */
	if (hdr->rcode != ERR_SUCCESSFUL) {
		switch (hdr->rcode) {
		case ERR_FORMAT:
			ttl = TTL_ERR_FORMAT;
			break;
		case ERR_FAILURE:
			ttl = TTL_ERR_FAILURE;
			break;
		case ERR_NAME:
			ttl = TTL_ERR_NAME;
			break;
		case ERR_NOTIMPLEMENTED:
			ttl = TTL_ERR_NOTIMPLEMENTED;
			break;
		case ERR_REFUSED:
			ttl = TTL_ERR_REFUSED;
			break;
		default:
			ttl = 0;
			break;
		}
		return ttl;
	}

	/* Dont accept packets with multiple queries */
	if (query_count != 1)
		return 0;

	/* Skip the Question Section */
	while(query_count--) {
		/* SANITY CHECK: 5 is the name '.' + qtype and qclass */
		if (data_size < 5)
			return 0;
		retval = name_decode(data, data_size, packet, NULL, 1);
		if (retval < 0) /* invalid name format */
			return 0;
		updatep(retval);
		if (data_size < 4) /* enough space for qtype and qclass? */
			return 0;
		updatep(4);
	}

	/* Get the minimun ttl of the RRs */
	while(data_size >= RRFIXEDSZ) {
		/* skip the name */
		retval = name_decode(data, data_size, packet, NULL, 1);
		if (retval < 0) /* invalid name format */
			return 0;
		updatep(retval);

		/* enough space for class, type, ttl, rrsize ? */
		if (data_size < 2+2+4+2)
			return 0;

		/* skip the dns class and type of the RR */
		updatep(4);

		/* finally we can read the TTL value, with any alignment */
		memcpy(&tmp32, data, 4);
		updatep(4);
		r_ttl = ntohl(tmp32);

		/* what matter is the minimum ttl */
		if (r_ttl < ttl)
			ttl = r_ttl;

		/* get the RR data size */
		rdata = (data[0] << 8) | data[1];
		updatep(2);

		/* skip the RR data size */
		if (data_size < rdata)
			return 0;
		updatep(rdata);
		if (data_size == 0)
			break;
	}
	return ttl;
}

#define DNS_MAX_INA	32
/* This function shifts the order of the IN/A RRs.
 * It isn't a true Round-Robin algorithm, since it shuffle
 * the records at random. We want not take information
 * about the latest address proposed as first address.
 *
 * WARNING: long and unclear function, but very commented */
void dns_shuffle(byte *packet, unsigned int packet_size)
{
	HEADER *hdr = (HEADER*) packet;
	int query_count = ntohs(hdr->qdcount);
	int answer_count = ntohs(hdr->ancount);
	byte *data = packet + sizeof(HEADER); /* data pointer */
	unsigned int data_size = packet_size - sizeof(HEADER); /* data size */
	int retval;
	u_int16_t rdata; /* RR data size */
	int n_rr = 0; /* Number of RR processed */
	char *name; /* name field of the RR */
	byte *ina[DNS_MAX_INA]; /* IN A RRs pointers table */
	int ina_id = 0; /* Index of the next element in the table */
	u_int16_t qclass, qtype;
	char currentname[MAXDNAME+1]; /* Current name field of the RR */
	char firstname[MAXDNAME+1]; /* name of the first A IN RR found */
	int i; /* just a counter */
	byte tmp[4]; /* Used to save an IPv4 address */

	/* packet_size should contain at least the header */
	if (packet_size < sizeof(HEADER))
		return;

	/* Shuffling not needed for DNS errors or if there is
	 * only one RR in the answer section */
	if (hdr->rcode != ERR_SUCCESSFUL ||
	    query_count != 1 ||
	    answer_count <= 1)
		return;

	/* initializations */
	for (i = 0; i < DNS_MAX_INA; i++)
		ina[i] = NULL;
	firstname[0] = '\0'; /* marked as not initialized */

	/* Skip the Question Section */
	while(query_count--) {
		/* sanity check: 5 is the name '.' + qtype and qclass */
		if (data_size < 5)
			return;
		retval = name_decode(data, data_size, packet, NULL, 1);
		if (retval < 0) /* invalid name format, name truncated, ... */
			return;
		updatep(retval);
		if (data_size < 4) /* enough space for qtype and qclass? */
			return;
		updatep(4);
	}

	/* build the IN/A pointers table */
	while(data_size >= RRFIXEDSZ) {
		n_rr++; /* RRs processed */

		/* skip the name */
		retval = name_decode(data, data_size, packet, &name, 1);
		if (retval < 0) /* invalid name or out of memory */
			return;
		updatep(retval);
		strlcpy(currentname, name, MAXDNAME+1); /* save it */
		free(name);

		/* enough space for class, type, ttl, rrsize ? */
		if (data_size < 2+2+4+2)
			return;

		/* it is a IN A RR? */
		qtype = (data[0] << 8) | data[1];
		qclass = (data[2] << 8) | data[3];
		if (qtype == T_A && qclass == C_IN) {
			/* If it's the first IN A RR or if it matches
			 * the name of the first IN A RR add it to the
			 * IN A address pointers list */
			if (firstname[0] == '\0' ||
			    !strcasecmp(firstname, currentname)) {
				/* enough space for the complete RR? */
				if (data_size < 14)
					return;
				ina[ina_id] = data+RRFIXEDSZ;
				ina_id++; /* increment the index */
				DEBUG(printf("SHUFFLE TABLE %s %p\n",
					currentname, data+10);)
			}
			/* If it was the first name save it */
			if (firstname[0] == '\0')
				memcpy(firstname, currentname,
					MAXDNAME+1);
		}

		/* skip class, type, ttl */
		updatep(8);

		/* get the RR data size and skip the two bytes size */
		rdata = (data[0] << 8) | data[1];
		updatep(2);

		/* skip the RR data size */
		if (data_size < rdata)
			return;
		updatep(rdata);

		/* Stop here if we reached the max pointers allowed,
		 * the end of the answer section or if there aren't no
		 * more data */
		if (n_rr == answer_count ||
		    data_size == 0 ||
		    ina_id == DNS_MAX_INA)
			break;
	}

	if (ina_id <= 1) /* nothing to shuffle */
		return;

	/* shuffle the IN A RRs address */
	DEBUG(printf("DO SHUFFLE\n");)
	for (i = 0; i < ina_id; i++) {
		int r = rand() % ina_id;
		/* swap */
		memcpy(tmp, ina[i], INADDRSZ);
		memcpy(ina[i], ina[r], INADDRSZ);
		memcpy(ina[r], tmp, INADDRSZ);
	}
}

int send_udp(int fd, void *packet, unsigned int size, struct sockaddr *to, int tolen)
{
        int retval;
	HEADER *hdr = (HEADER*) packet;

	/* UDP truncation */
	if (size > PACKETSZ) {
		size = PACKETSZ;
		hdr->tc = 1; /* truncation flag ON */
	}

        retval = sendto(fd, packet, size, 0, to, tolen);
        if (retval == -1) {
                perror("[send_udp] sendto");
        }
        return retval;
}

/* Send a TCP DNS response */
int send_tcp(byte *packet, int len, int sd)
{
	u_int16_t size;
	int retval;
	HEADER *hdr = (HEADER*) packet;

	/* TCP truncation */
	if (len > TCPPACKETSZ) {
		len = TCPPACKETSZ;
		hdr->tc = 1; /* truncation flag ON */
	}
        size = htons(len);

	if (send(sd, &size, 2, 0) == -1) {
		perror("[send_tcp] send");
		return -1;
	}
	retval = send(sd, packet, len, 0);
	if (retval == -1)
		perror("[send_tcp] send");
	return retval;
}

/* Get the question section */
static byte *get_qsection(byte *packet, unsigned int size, int *qsize)
{
	char *name = NULL;
	char *qsection = NULL;
	char *encoded = NULL;
	int retval, encoded_size;

	if (size < sizeof(HEADER)+5) goto out;
	retval = name_decode(packet+sizeof(HEADER), size-sizeof(HEADER),
		packet, &name, 1);
	if (name == NULL) {
		*qsize = retval;
		goto out;
	}
	if (size < sizeof(HEADER)+retval+4) goto out;
	encoded = (char*)name_encode(name, &encoded_size, '.');
	if (encoded == NULL) {
		*qsize = encoded_size;
		goto out;
	}
	qsection = malloc(encoded_size+4);
	if (qsection == NULL) {
		*qsize = YK_NOMEM;
		goto out;
	}
	memcpy(qsection, encoded, encoded_size);
	memcpy(qsection+encoded_size, packet+sizeof(HEADER)+retval, 4);
	free(name);
	free(encoded);
	/* the caller must free qsection */
	*qsize = encoded_size+4;
	return (byte*) qsection;
out:
	free(name);
	free(qsection);
	free(encoded);
	return NULL;
}

void send_udp_error(int fd, struct sockaddr *from, int fromlen, byte *packet, unsigned int size, int error_type)
{
	byte *error;
	int errsize;

	error = build_error(&errsize, packet, size, error_type);
	if (error == NULL)
		return;
	send_udp(fd, error, errsize, from, fromlen);
	free(error);
}

void send_tcp_error(int sd, byte *packet, unsigned int size, int error_type)
{
	byte *error;
	int errsize;

	error = build_error(&errsize, packet, size, error_type);
	if (error == NULL)
		return;
	send_tcp(error, errsize, sd);
	free(error);
}

byte *build_error(int *retsize, byte *packet, unsigned int size, int error_type)
{
	HEADER error_header;
	HEADER *hdr = (HEADER*) packet;
	byte *question;
	byte *error;
	int question_size;
	int errsize = 0;

	memset(&error_header, 0, sizeof(HEADER));
	error_header.id = hdr->id;
	error_header.qr = 1;
	error_header.opcode = hdr->opcode;
	error_header.aa = 0;
	error_header.tc = 0;
	error_header.rd = 0;
	error_header.ra = 1;
	error_header.unused = 0;
	error_header.rcode = error_type;
	error_header.qdcount = 0;
	error_header.ancount = 0;
	error_header.nscount = 0;
	error_header.arcount = 0;
	errsize += sizeof(HEADER);
	switch(error_type) {
	case ERR_FAILURE:
	case ERR_NAME:
	case ERR_REFUSED:
		if ((question = get_qsection(packet, size, &question_size)) != NULL) {
			error = malloc(sizeof(HEADER)+question_size);
			if (error == NULL) {
				perror("[send_error] malloc");
				return NULL;
			}
			error_header.qdcount = htons(1);
			memcpy(error, &error_header, sizeof(HEADER));
			memcpy(error+sizeof(HEADER), question, question_size);
			free(question);
			errsize += question_size;
			*retsize = errsize;
			return error;
		}
	default:
		error = malloc(sizeof(HEADER));
		if (error == NULL) {
			perror("[send_error] malloc");
			return NULL;
		}
		memcpy(error, &error_header, sizeof(HEADER));
		*retsize = sizeof(HEADER);
		return error;
		break;
	}
	return NULL; /* unreached */
}

/* Decode the name pointed by *ptr.
 * data_size is the size of the packet starting from ptr
 * *base     is the pointer to the packet head
 * **name    will contain the dynamic allocated decoded name
 * compr     must be 0 if pointers are not allowed, otherwise 1.
 *
 * If **name is NULL the function don't allocate any memory
 * and can be used just to obtain the len of the name to skip
 * it.
 */
#define DNS_NAME_NESTEDPTR_MAX	64
int name_decode(byte *ptr, int data_size, byte *base, char **name, int compr)
{
	unsigned int size = 0; /* The size of the decoded name */
	int realsize = 0; /* The size of the encoded name processed */
	int n_compr = 0; /* nested pointers level */
	int max_compr; /* max nested pointers allowed */
	char buf[MAXDNAME+1]; /* Include space for nul term */

	/* set the max nested pointers allowed */
	max_compr = compr ? DNS_NAME_NESTEDPTR_MAX : 1;

	/* data size must be at least 1 */
	if (data_size < 1)
		goto format_error;

	while(*ptr) {
		byte label_size = 0;

		/* handle the DNS name pointers */
		if ((*ptr & 0xc0) == 0xc0 && n_compr < max_compr) {
			byte pointer_b[2];
			u_int16_t pointer;

			n_compr++;
			/* the label is two bytes */
			if (data_size < 2)
				goto format_error;

			/* get the offset */
			pointer_b[0] = *ptr & (~0xc0);
			pointer_b[1] = *(ptr+1);
			/* Fix the endianess */
			pointer = (pointer_b[0] << 8) | pointer_b[1];

			/* The label can't point inside the header */
			if (pointer < sizeof(HEADER))
				goto format_error;

			/* jump! */
			data_size = data_size+(ptr-base)-pointer;
			ptr = base+pointer;

			/* sanity check */
			if (data_size <= 0)
				goto format_error;
			/* We must add the two bytes of pointer to
			 * the real size, only for the first
			 * pointer */
			if (n_compr == 1)
				realsize += 2;
			continue;
		} else if ((*ptr & 0xc0) == 0xc0 && n_compr >= compr) {
			/* max nested label reached, game over */
			goto format_error;
		}

		/* The name has the first two bits set to 01 or 10 ?
		 * this format is reserved, it's an error */
		if ((*ptr & 0xc0) == 0x40 || (*ptr & 0xc0) == 0x80)
			goto format_error;

		/* If unsigned char is 8 bit we dont need to check
		 * that label_size is more than 63. We take the assumption. */
		label_size = *ptr & 0x3f; /* the size of this label */

		/* data_size must be large enough to contain the label size,
		 * the label (*ptr bytes) and _at least_ the nul term */
		if (data_size < label_size+2)
			goto format_error;

		/* check if there is enough space for label and '.' */
		if (size+label_size+1 > MAXDNAME)
			goto format_error;
		/* copy the label, that start at ptr+1 and is *ptr bytes */
		memcpy(buf+size, ptr+1, label_size);
		/* add the '.' */
		*(buf+size+label_size) = '.';
		/* update the offsets */
		/* Increment the realsize if we never jumpted to some pointer */
		if (n_compr == 0)
			realsize += label_size+1;
		data_size -= label_size+1;
		size += label_size+1;
		ptr += label_size+1;
	}

	if (size == 0) { /* the root '.' */
		*(buf) = '.';
		*(buf+1) = '\0';
	} else {
		/* the string NULL term */
		*(buf+size) = '\0';
	}

	if (name) {
		*name = strdup(buf);
		if (*name == NULL) /* Out of memory */
			return YK_NOMEM;
	}

	if (n_compr > 0)
		return realsize;
	else
		return realsize+1; /* +1 is for the name nul term */

format_error:
	if (name)
		*name = NULL;
	return YK_INVALID;
}

/* Encode a DNS name,
 * the names a.b.c. and a.b.c will be encoded in the same bytes.
 *
 * *msg  points to the name, rappresented as zero or more labels
 *       separated by the character `sep'.
 * *size will contain the size of the encoded name in not NULL.
 * sep   is the separator character used.
 *
 * The function returns a malloc()ated buffer of *size bytes
 * with the encoded name on success, otherwise it returns NULL
 */
byte *name_encode(char *msg, int *size, char sep)
{
	byte buf[MAXCDNAME];
	char *p = msg, *last = msg;
	byte *tmp;
	unsigned int label_len, encoded_size = 0;

	while(1) {
		p = strchr(p, sep);
		label_len = (p != NULL) ? (p - last) : (signed)strlen(last);
		if (label_len == 0) { /* end of the name */
			break;
		} else if (label_len > MAXLABEL) { /* out of range label len */
			goto invalid;
		}
		if (encoded_size+label_len+1 > MAXCDNAME)
			goto invalid;
		*(buf+encoded_size) = label_len;
		encoded_size++;
		memcpy(buf+encoded_size, last, label_len);
		encoded_size += label_len;
		if (p == NULL) /* end of the name */
			break;
		p++;
		last = p;
	}
	/* Add the DNS name nul term */
	if (encoded_size+1 > MAXCDNAME)
		goto invalid;
	*(buf+encoded_size) = 0;
	encoded_size++;

	if (size) *size = encoded_size;
	/* Out of memory */
	if ((tmp = malloc(encoded_size)) == NULL)
		goto oom;
	memcpy(tmp, buf, encoded_size);
	return tmp;

oom:		/* out of memory */
	if (size) *size = YK_NOMEM;
	return NULL;

invalid:	/* Invalid name */
	if (size) *size = YK_INVALID;
	return NULL;
}
