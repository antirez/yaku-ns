/* htkey.c
 * Translate a Resource Record reference to the hash table key
 *
 * Copyright (C) 2000 Salvatore Sanfilippo
 * Copyright (C) 2001 Salvatore Sanfilippo
 * Copyright (C) 2002 Salvatore Sanfilippo
 * <antirez@invece.org>
 *
 * This code is under the GPL license
 * See the COPYING file for more information
 */

#include "ens.h"
#include <string.h>
#include <ctype.h>

#include "aht.h"

/* Key format:
 *
 * [klen][seq][type][class][name]
 *
 * The key is not nul terminated, fields description:
 *
 * klen:  2 bytes total key length (including itself)
 * seq:   4 bytes sequence number, to distinguish and access to multiple
 *        entries with the same RR type/class/name.
 * type:  RR type
 * class: RR class
 * name:  RR name
 *
 * The format was changed the 2002-09-09. The change was needed to
 * support the new AHT hash-table library */
size_t rr_to_key(char *dest, size_t dsize, char *name, u_int16_t type,
		u_int16_t class, u_int32_t seq)
{
	size_t l = strlen(name);
	u_int16_t ltwo;
	unsigned int i;
	char *p;

	yakuns_assert(dsize >= 33);
	memcpy(dest+2, &seq, 4);
	memcpy(dest+6, &type, 2);
	memcpy(dest+8, &class, 2);
	l = (l > dsize-10) ? (dsize-10) : l;
	memcpy(dest+10, name, l);
	p = dest+10;
	/* put it lowercase -- but note that we save the resource
	 * record with the original case to avoid useless information
	 * leak */
	for (i = 0; i < l; i++)
		p[i] = tolower(p[i]);
	ltwo = l;
	memcpy(dest, &ltwo, 2);
	return 10 + l;
}

/* Compare two keys */
int ht_dnskey_compare(void *key1, void *key2)
{
	u_int16_t k1l, k2l;

	memcpy(&k1l, key1, 2);
	memcpy(&k2l, key2, 2);
	if (k1l != k2l)
		return 0; /* keys of different length can't match */
	return !memcmp(key1, key2, k1l);
}

/* Hash a given key */
u_int32_t ht_dnskey_hash(void *key)
{
	u_int16_t l;

	memcpy(&l, key, 2);
	return ht_strong_hash(key, l, 0x11223344);
}
