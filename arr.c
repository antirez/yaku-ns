/* arr.c
 * Additonal Resource Records
 * (check the function build_response() in dns.c for more related code)
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

/* not exported functions */

/* exported functions */
int additional_rr_needed(struct additionalrr *arr, struct RRentry *rr, int arrindex);

/* Use ONLY this macro to add the next ARR, this automatically
 * takes the count of the max additional ARR allowed and free the
 * allocated memory for the name if the ARR list is full. */
#define ADD_ARR(arrtype, arrclass, arrname) \
do { \
	if (arrindex+additional_count < MAX_ADDRR) {\
		arr->qtype = (arrtype); \
		arr->qclass = (arrclass); \
		arr->name = (arrname); \
		additional_count++; \
		arr++; \
	} else { \
		free(arrname); \
	} \
} while(0)

/* This function is called for every Resource Record added to the response:
 * it compiles a list of the additional RR needed, for every requested
 * RR. For example if the query_processor() adds an MX IN RR, when
 * it calls this function the additioanl RR list will be populated with
 * an A IN RR. Warning: This function doesn't add the RR in the packet,
 * it just compile the list of the RRs that will be useful to add. The
 * additional RRs are added (usually) by the caller function. */
int additional_rr_needed(struct additionalrr *arr, struct RRentry *rr, int arrindex)
{
	int additional_count = 0;

	/* MX needs an additional A RR with the address of the mail exchange */
	if (rr->qtype == T_MX) {
		byte *mxname_pointer;
		char *mxname;
		int retval;

		/* compute the offset to find the name inside the MX record */
		mxname_pointer = rr->data+sizeof(struct RR_MX);
		retval = name_decode(mxname_pointer,
			(rr->size)-sizeof(struct RR_MX), NULL, &mxname, 0);
		yakuns_assert(retval != YK_INVALID);
		if (retval == YK_NOMEM)
			goto out;
		ADD_ARR(T_A, C_ANY, mxname);
	}

	/* NS needs an additional A RR with the address of the name server */
	if (rr->qtype == T_NS) {
		byte *nsname_pointer;
		char *nsname;
		int retval;

		/* compute the offset to find the name inside the NS record */
		nsname_pointer = rr->data;
		retval = name_decode(nsname_pointer,
			rr->size, NULL, &nsname, 0);
		yakuns_assert(retval != YK_INVALID);
		if (retval == YK_NOMEM)
			goto out;
		ADD_ARR(T_A, C_ANY, nsname);
	}

out:
	/* add the nul term */
	arr->qtype = 0;
	arr->qclass = 0;
	arr->name = NULL;
	return additional_count;
}
