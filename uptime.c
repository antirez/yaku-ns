/* uptime.c
 * Uptime over DNS
 *
 * Copyright (C) 2000,2001,2002 by Salvatore Sanfilippo
 * <antirez@invece.org>
 *
 * This code is under the GPL license
 * See the COPYING file for more information
 */

/* ens.h must be included before all other includes */
#include "ens.h"

#include <time.h>
#include <stdlib.h>

#define YAKU_UPTIME_RR_NAME "uptime.yaku"

/* global vars */
int opt_uptime = 0;
time_t ens_start;

/* not exported functions */

/* exported functions */
int uptime_refresh(void);

/* -------------------------------------------------------------------------- */
/* Usually called once every second, this function updates the
 * uptime.yaku TXT CHAOS RR in the local table. */
int uptime_refresh(void)
{
	struct RRentry *uptimerr = NULL;
	char buffer[1024];
	byte *encoded_uptime;
	int encoded_uptime_size;
	time_t uptime;

	uptimerr = local_search(YAKU_UPTIME_RR_NAME".", T_TXT, C_CHAOS, 0);
	if (uptimerr == NULL) {
		uptimerr = alloc_rr(YAKU_UPTIME_RR_NAME, T_TXT, C_CHAOS, 1);
		if (uptimerr == NULL)
			return -1;
		uptimerr->data[0] = 0;
		uptimerr->ttl = 0;
		local_add_entry(uptimerr);
	}
	uptime = get_sec() - ens_start;
	snprintf(buffer, 1024, "%ld days,%ld hours,%ld minutes,%ld seconds",
		uptime/86400,
		(uptime%86400)/3600,
		((uptime%86400)%3600)/60,
		((uptime%86400)%3600)%60);
	encoded_uptime = name_encode(buffer, &encoded_uptime_size, ',');
	if (encoded_uptime == NULL)
		return encoded_uptime_size;
	encoded_uptime_size--;
	free(uptimerr->data);
	uptimerr->data = encoded_uptime;
	uptimerr->size = encoded_uptime_size;
	return 0;
}
