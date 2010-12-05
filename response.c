/* response.c
 * Local responses building
 *
 * Copyright (C) 2000,2001,2002 by Salvatore Sanfilippo
 * <antirez@invece.org>
 *
 * This code is under the GPL license version 2
 * See the COPYING file for more information
 */

/* ens.h must be included before all other includes */
#include "ens.h"

#include <stdlib.h>

#define MAX_RR 256

/* exported functions */
byte *build_response(u_int16_t qclass, u_int16_t qtype, char *qname, char *name, byte *query, int query_size, HEADER *hdr, int *size, int maxsize);

/* -------------------------------------------------------------------------- */

/* This function builds a complete DNS response.
 * The maxsize parameter doesn't specify the maximum size of the
 * response returned, but the maximum size of the DNS packet under
 * the used protocol (for example 512 for UDP). This information
 * is used to leave the additional information out if there isn't
 * space left, but the real DNS truncation is done in the
 * function that sends the packet. */
byte *build_response(u_int16_t qclass, u_int16_t qtype, char *qname, char *name, byte *query, int query_size, HEADER *hdr, int *size, int maxsize)
{
	byte *response = NULL;
	int response_size = 0;
	int j; /* counter */
	int ret, retsize;
	struct additionalrr arr[MAX_ADDRR+1] = { {NULL, 0, 0} };
	int arr_index = 0;
	char *p, canonical[MAXDNAME];
	struct RRentry *rrs[MAX_RR], *cnamerr = NULL;
	int cname_chainlen = 0;

	/* Get pointers to matching RRs */
	ret = local_search_all(name, qtype, qclass, rrs, MAX_RR);

	/* No match? check if it is a CNAME for something.
	 * XXX: we don't follow CNAME chains for now... it should
	 * either implemented or not allowed in the configuration */
	if (!ret) {
		while(cname_chainlen < CNAME_CHAIN_MAX) {
			if ((cnamerr = local_search(name, T_CNAME, qclass, 0)))
			{
				int retval;
				char *canonicalp;

				retval = name_decode(cnamerr->data,
						cnamerr->size,
						NULL, &canonicalp, 0);
				if (retval == YK_NOMEM)
					goto out;
				strlcpy(canonical, canonicalp, MAXDNAME);
				free(canonicalp);

				/* Reiterate the search using the
				 * canonical name */
				ret = local_search_all(canonical, qtype, qclass,
						rrs, MAX_RR);
				ret ++;
				break;
			}
			break; /* Don't follow CNAME chains for now */
		}
	}

	/* Add the matching RRs in the answer section */
	if (ret) {
		byte *tmp;

		/* Build the header if needed */
		if (!response) {
			retsize = build_header(&response, hdr, 1);
			if (retsize == YK_NOMEM)
				goto out;
			response_size += retsize;
		}

		/* Copy the original query in the question section */
		tmp = realloc(response, response_size+query_size);
		if (tmp == NULL)
			goto out;
		response = tmp;
		memcpy(response+response_size, query, query_size);
		response_size += query_size;

		/* Add the CNAME RR, if it was a CNAME match */
		if (cnamerr) {
			ret --;
			retsize = add_rr(&response, hdr, cnamerr,
					response_size, AN_SECTION, maxsize);
			if (retsize < 0)
				goto out;
			response_size += retsize;
			/* Our RRs must refer to the canonical name */
			qname = canonical;
		}

		/* Add the matching RRs found */
		for (j = 0; j < ret; j++) {
			struct RRentry *rr = rrs[j];

			/* build the needed Additional RRs list */
			arr_index += additional_rr_needed(&arr[arr_index],
				rrs[j], arr_index);

			/* add the RR. Note that even if we matched a wildcard
			 * local RR, we add the requested name in the query */
			rr->name = qname;
			/* ready to add the RR i the response */
			retsize = add_rr(&response, hdr, rr,
				response_size, AN_SECTION, maxsize);
			if (retsize < 0)
				goto out;
			response_size += retsize;
		}
	}

	/* Add the authority section */
	if (response) {
		ret = local_search_all(name, T_NS, C_ANY, rrs, MAX_RR);
		if (ret == 0) {
			int l = strlen(name);
			char *namecopy = alloca(l + 1);

			memcpy(namecopy, name, l+1);
			if ((p = strchr(namecopy, '.')) == NULL)
				goto as_out; /* skip the authority sect. code */
			if (*(p+1) != '\0')
				p++;
			ret = local_search_all(p, T_NS, C_ANY, rrs, MAX_RR);
		}

		if (ret != 0) {
			for (j = 0; j < ret; j++) {
				DEBUG(log(VERB_DEBUG, "Needed ARR %s %s %s\n",
					qtype_to_str(rrs[j]->qtype),
					qclass_to_str(rrs[j]->qclass),
					rrs[j]->name);)
				arr_index += additional_rr_needed(
					&arr[arr_index], rrs[j], arr_index);

				/* add the RR */
				retsize = add_rr(&response, hdr, rrs[j],
					response_size, NS_SECTION, maxsize);
				if (retsize < 0)
					goto out;
				response_size += retsize;
			}
		}
	}
as_out:
	/* We can add the Additional RRs at this point, we compiled
	 * the list of additional RRs to add inside the while() above.
	 * XXX: add C_ANY and T_ANY checks, after reading RFCs */
	for (j = 0; response && j < MAX_ADDRR && arr[j].name; j++) {
		int l, already = 0;

		DEBUG(log(VERB_DEBUG, "Adding ARR for %s %s %s\n",
			qtype_to_str(arr[j].qtype),
			qclass_to_str(arr[j].qclass),
			arr[j].name);)
		/* Avoid duplications: usually additional RRs are
		 * few so the linear search seems the faster way */
		for (l = 0; l < j; l++) {
			if (	arr[j].qtype == arr[l].qtype &&
				arr[j].qclass == arr[l].qclass &&
				strcasecmp(arr[j].name, arr[l].name) == 0)
			{
				already = 1;
				break;
			}
		}
		if (already)
			continue;

		/* Search and add the matching RRs:
		 * of course there isn't additional RRs processing
		 * for the additional RRs :) */
		ret = local_search_all(arr[j].name, arr[j].qtype,
					arr[j].qclass, rrs, MAX_RR);
		DEBUG(log(VERB_DEBUG, "Found %d matching RRs for it\n", ret);)
		if (ret) {
			int c;
			for (c = 0; c < ret; c++) {
				/* add the RR */
				retsize = add_rr(&response, hdr, rrs[c],
					response_size, AR_SECTION, maxsize);
				if (retsize < 0)
					goto out;
				response_size += retsize;
			}
		}
	}

	/* free the additional RR entry allocated */
	for (j = 0; j <= MAX_ADDRR; j++) {
		arr[j].qtype = 0;
		arr[j].qclass = 0;
		if (arr[j].name != NULL) {
			free (arr[j].name);
			arr[j].name = NULL;
		}
	}
	*size = response_size;
	return response;

out:
	free(response);
	*size = YK_NOMEM;
	return NULL;
}
