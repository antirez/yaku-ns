/* Get a zone using AXFR under TCP
 * produce as output a yaku-ns config file.
 *
 * Copyright(C) 2001,2002 Salvatore Sanfilippo
 * <antirez@invece.org>
 *
 * This software is under the GPL license version 2
 *
 * TODO:
 * - should get only the RRs concerning to the zone requested
 */

#include "ens.h"
#ifdef perror
#undef perror
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

char *opt_zone = NULL;
char *opt_server = NULL;
int opt_port = NAMESERVER_PORT;

void usage(void);
void get_zone(char *zone, char *server, int port);
void decode_response(byte *packet, unsigned int packet_size);
void output_rr(char *rrname, u_int16_t qtype, u_int16_t qclass, u_int32_t ttl, byte *base, byte *data, u_int16_t rdata, int commented);
int dump_ipv4(byte *data, unsigned int rdata);
int dump_name(byte *base, byte *data, unsigned int rdata);
int dump_u16(byte *data, unsigned int rdata);
int dump_u32(byte *data, unsigned int rdata);
int dump_txt(byte *data, unsigned int rdata);
void remove_trailer_dot(char *name);

int main(int argc, char **argv)
{
	int c;

	while ((c = getopt(argc, argv, "z:s:p:")) != EOF) {
		switch(c) {
		case 'z':
			opt_zone = strdup(optarg);
			break;
		case 's':
			opt_server = strdup(optarg);
			break;
		case 'p':
			opt_port = atoi(optarg);
			break;
		case '?':
			usage();
			exit(1);
		}
	}

	if (!opt_zone || !opt_server) {
		usage();
		exit(1);
	}

	get_zone(opt_zone, opt_server, opt_port);

	return 0;
}

void usage(void)
{
	printf( "getzone (yaku-ns)\n"
		"usage: getzone -z <zone> -s <server IP> [-p <port>]\n");
}

int build_query_header(byte **dest, u_int16_t id, unsigned int rd)
{
	HEADER *hdr;

	hdr = malloc(sizeof(HEADER));
	if (hdr == NULL)
		return -1;
	memset(hdr, 0, sizeof(HEADER));
	hdr->id = id;
	hdr->qr = 0;
	hdr->opcode = QUERY;
	hdr->aa = 0;
	hdr->tc = 0;
	hdr->rd = rd;
	hdr->ra = 0;
	hdr->qdcount = htons(1);

	*dest = (byte*) hdr;
	return sizeof(HEADER);
}

int add_question_section(byte **dest, int size, char *name, u_int16_t qtype,
							    u_int16_t qclass)
{
	byte *encname, *tmp;
	int encname_size;
	int qsection_size;
	u_int16_t tmp16;

	if ((encname = name_encode(name, &encname_size, '.')) == NULL)
		return -1;

	qsection_size = 4 + encname_size;
	tmp = realloc(*dest, size + qsection_size);
	if (tmp == NULL)
		return -1;
	*dest = tmp;
	tmp += size;
	memcpy(tmp, encname, encname_size);
	tmp16 = htons(qtype);
	memcpy(tmp+encname_size, &tmp16, 2);
	tmp16 = htons(qclass);
	memcpy(tmp+encname_size+2, &tmp16, 2);
	return qsection_size;
}

void send_zone_request(int fd, char *zone)
{
	int size = 0;
	int retval;
	byte *query = NULL;

	/* Query header */
	if ((retval = build_query_header(&query, 0, 0)) == -1)
		goto oom;
	size += retval;

	/* Query question section */
	retval = add_question_section(&query, size, zone, T_AXFR, C_IN);
	if (retval == -1)
		goto oom;
	size += retval;

	/* Send the request */
	if (send_tcp(query, size, fd) == -1) {
		perror("send_tcp");
		exit(1);
	}
	return;

oom: /* out of memory or name encoding problems */
	fprintf(stderr, "Error\n");
	exit(1);
}

int open_server(char *ip, int port)
{
	int s;
	struct sockaddr_in sa;

	if ((s = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		return -1;
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	if (inet_aton(ip, &sa.sin_addr) == 0) {
		close(s);
		return -1;
	}
	if (connect(s, (struct sockaddr*) &sa, sizeof(sa)) == -1) {
		close(s);
		return -1;
	}
	return s;
}

void get_zone_response(int fd)
{
	int n_read, left;
	u_int16_t response_size;
	byte tmp[2];
	byte *response;

	while(1) {
		/* Read the response */
		n_read = recv(fd, tmp, 2, 0);
		if (n_read == 0)
			break;
		if (n_read != 2) {
			fprintf(stderr, "Error reading the response size\n");
			exit(1);
		}
		response_size = (tmp[0] << 8) | tmp[1];
		if (response_size < sizeof(HEADER))
			goto invalid;
		response = malloc(response_size);
		if (!response) {
			fprintf(stderr, "Out of memory\n");
			exit(1);
		}
		left = response_size;
		while(left) {
			n_read = recv(fd, response+response_size-left, left, 0);
			if (n_read <= 0)
				goto invalid;
			left -= n_read;
		}
		decode_response(response, response_size);
		free(response);
	}
	return;

invalid:
	fprintf(stderr, "Invalid response\n");
	exit(1);
}

void decode_response(byte *packet, unsigned int packet_size)
{
	static int soa_flag = 0;
	HEADER *hdr = (HEADER*) packet;
	int query_count = ntohs(hdr->qdcount);
	int answer_count = ntohs(hdr->ancount);
	byte *data = packet + sizeof(HEADER);
	int data_size = packet_size - sizeof(HEADER);
	int retval, rdata;
	u_int32_t ttl, tmp32;
	u_int16_t qtype, qclass, tmp16;
	char rrname[MAXDNAME+1];

	/* packet_size should contain at least the header */
	if (packet_size < sizeof(HEADER))
		return;

	/* Skip the Question Section */
	while(query_count--) {
		/* SANITY CHECK: 5 is the name '.' + qtype and qclass */
		if (data_size < 5)
			return;
		retval = name_decode(data, data_size, packet, NULL, 1);
		if (retval == -1) /* invalid name format */
			return;
		updatep(retval);
		if (data_size < 4) /* enough space for qtype and qclass? */
			return;
		updatep(4);
	}

	while(answer_count--) {
		char *name;

		/* skip the name */
		retval = name_decode(data, data_size, packet, &name, 1);
		if (retval == -1) /* invalid name format */
			return;
		strlcpy(rrname, name, MAXDNAME+1);
		free(name);
		updatep(retval);
		remove_trailer_dot(rrname);

		/* enough space for class, type, ttl, rrsize ? */
		if (data_size < 2+2+4+2)
			return;

		/* skip the dns class and type of the RR */
		memcpy(&tmp16, data, 2);
		qtype = htons(tmp16);
		memcpy(&tmp16, data+2, 2);
		qclass = htons(tmp16);
		updatep(4);

		/* finally we can read the TTL value, with any alignment */
		memcpy(&tmp32, data, 4);
		ttl = ntohl(tmp32);

		/* skip the TTL field */
		updatep(4);

		/* get the RR data size */
		rdata = (data[0] << 8) | data[1];
		updatep(2);

		/* skip the RR data size */
		if (data_size < rdata)
			return;

		/* Output the RR */
		/* Comment the second SOA to avoid duplication */
		output_rr(rrname, qtype, qclass, ttl, packet, data, rdata,
				(soa_flag == 1 && qtype == T_SOA));

		/* Check for SOA */
		if (qtype == T_SOA)
			soa_flag++;
		if (soa_flag == 2)
			exit(0);

		updatep(rdata);
		if (data_size == 0)
			break;
	}
}

void get_zone(char *zone, char *server, int port)
{
	int fd;

	/* Contact the server */
	fd = open_server(server, port);
	if (fd == -1) {
		perror("Can't open the TCP connection");
		exit(1);
	}

	/* Send the request */
	send_zone_request(fd, zone);

	/* Get and decode the response */
	get_zone_response(fd);
}

void output_rr(	char *rrname,
		u_int16_t qtype,
		u_int16_t qclass,
		u_int32_t ttl,
		byte *base,
		byte *data,
		u_int16_t rdata,
		int commented)
{
	static u_int32_t last_ttl = -1;
	static u_int16_t last_qclass = -1;
	int x, i;

	if (last_qclass != qclass) {
		if (commented) printf("# ");
		switch(qclass) {
		case C_IN:
			printf("Class IN\n");
			break;
		case C_CHAOS:
			printf("Class CHAOS\n");
			break;
		case C_ANY:
			printf("Class ANY\n");
			break;
		default:
			return;
		}
		last_qclass = qclass;
	}

	if (last_ttl != ttl) {
		if (commented) printf("# ");
		printf("TTL %u\n", ttl);
		last_ttl = ttl;
	}

	if (commented) printf("# ");
	switch(qtype) {
	case T_A:
		x = dump_ipv4(data, rdata);
		printf(" %s\n", rrname);
		break;
	case T_AAAA:
		printf("#AAAA %s ... not supported\n", rrname);
		break;
	case T_NS:
		printf("NS %s ", rrname);
		x = dump_name(base, data, rdata);
		printf("\n");
		break;
	case T_MX:
		printf("MX %s ", rrname);
		x = dump_u16(data, rdata);
		rdata -= x;
		data += x;
		printf(" ");
		x = dump_name(base, data, rdata);
		printf("\n");
		break;
	case T_PTR:
		printf("PTR %s ", rrname);
		x = dump_name(base, data, rdata);
		printf("\n");
		break;
	case T_TXT:
		printf("TXT %s ", rrname);
		x = dump_txt(data, rdata);
		printf("\n");
		break;
	case T_CNAME:
		printf("#CNAME %s ", rrname);
		x = dump_name(base, data, rdata);
		printf("\n");
		break;
	case T_SOA:
		printf("SOA %s ", rrname);
		x = dump_name(base, data, rdata);
		rdata -= x;
		data += x;
		printf(" ");
		x = dump_name(base, data, rdata);
		rdata -= x;
		data += x;
		for (i = 0; i < 5; i++) {
			printf(" ");
			x = dump_u32(data, rdata);
			rdata -= x;
			data += x;
		}
		printf("\n");
		break;
	default:
		printf("#### unsupported RR (type: %u) %s\n", qtype, rrname);
		break;
	}
	return;
}

void format_error(void)
{
	fprintf(stderr, "RR format error\n");
	exit(1);
}

int dump_ipv4(byte *data, unsigned int rdata)
{
	struct in_addr ia;
	if (rdata < sizeof(ia))
		format_error();
	memcpy(&ia, data, sizeof(ia));
	printf("%s", inet_ntoa(ia));
	return sizeof(ia);
}

int dump_name(byte *base, byte *data, unsigned int rdata)
{
	int retval;
	char *name;

	retval = name_decode(data, rdata, base, &name, 1);
	if (retval < 0)
		format_error();
	remove_trailer_dot(name);
	printf("%s", name);
	free(name);
	return retval;
}

int dump_u16(byte *data, unsigned int rdata)
{
	u_int16_t tmp16;

	if (rdata < 2)
		format_error();
	memcpy(&tmp16, data, 2);
	printf("%u", ntohs(tmp16));
	return 2;
}

int dump_u32(byte *data, unsigned int rdata)
{
	u_int32_t tmp32;

	if (rdata < 4)
		format_error();
	memcpy(&tmp32, data, 4);
	printf("%u", ntohl(tmp32));
	return 4;
}

int dump_txt(byte *data, unsigned int rdata)
{
	char label[MAXLABEL+1];
	unsigned int lsize;

	while (rdata) {
		if (rdata < 1)
			format_error();
		lsize = *data;
		rdata--;
		data++;
		if (lsize > MAXLABEL)
			format_error();
		if (rdata < lsize)
			format_error();
		memcpy(label, data, lsize);
		label[lsize] = '\0';
		printf("%s\\", label);
		rdata -= lsize;
		data += lsize;
	}
	return rdata;
}

void remove_trailer_dot(char *name)
{
	int l = strlen(name);
	if (l > 1) {
		if (name[l-1] == '.')
			name[l-1] = '\0';
	}
}

int log(int level, char *fmt, ...)
{
	ARG_UNUSED(level);
	ARG_UNUSED(fmt);
	return 0;
}
