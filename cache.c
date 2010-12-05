/* cache.c
 * ENS cache
 *
 * Copyright (C) 2000,2001,2002 by Salvatore Sanfilippo
 * <antirez@invece.org>
 *
 * This code is under the GPL license version 2
 * See the COPYING file for more information
 *
 * STATUS
 *
 * OK:      behaves as desidered
 * TODO:    behaves in some different way or the
 *          feature is not supported.
 * IGNORED: behaves in some different way since it
 *          is wanted.
 *
 * RFC 1035:
 * o Using the cache, should NOT be cached:
 *     o Cached RRs TTL should conceptually cont down: OK
 *     o When several RRs of the same type are available for a
 *       particular owner name, the resolver should either cache them
 *       all or none at all: IGNORED, ENS caches the whole datagram.
 *     o When a response is truncated, and a
 *       resolver doesn't know whether it has a complete set, it should
 *       not cache a possibly partial set of RRs: OK
 *     o Cached data should never be used in preference to
 *       authoritative data, so if caching would cause this to happen
 *       the data should not be cached: OK, we first try to meet the
 *       request using the local Resource Records.
 *     o The results of an inverse query should not be cached: IGNORED
 *       since inverse query aren't supported.
 *     o Should not be cached:
 *       The results of standard queries where the QNAME contains "*"
 *       labels if the data might be used to construct wildcards.  The
 *       reason is that the cache does not necessarily contain existing
 *       RRs or zone boundary information which is necessary to
 *       restrict the application of the wildcard RRs: TODO
 *     o RR data in responses of dubious reliability.  When a resolver
 *       receives unsolicited responses or RR data other than that
 *       requested, it should discard it without caching it.  The basic
 *       implication is that all sanity checks on a packet should be
 *       performed before any of it is cached: OK
 *     o In a similar vein, when a resolver has a set of RRs for some
 *       name in a response, and wants to cache the RRs, it should check
 *       its cache for already existing RRs: ENS cache the whole response
 *       packet, not single RRs, so it don't cache responses to a query
 *       if there is already a response for the same query in the cache.
 */

/* ens.h must be included before all other includes */
#include "ens.h"

unsigned int cache_count = 0;		/* number of cached responses */

#include <string.h>
#include <stdlib.h>
#include "aht.h"

/* global vars */
struct hashtable cache_table;
unsigned int cache_max = CACHE_MAX;
unsigned int cache_maxttl = CACHE_MAX_TTL;
unsigned int cache_minttl = CACHE_MIN_TTL;
int opt_cachenoexpire = 0;

/* not exported functions */
static u_int32_t cache_get_min_ttl(byte *packet, int packet_size);

/* exported functions */
void cache_add_entry(struct forwardentry *p, byte *packet, int packet_size);
void cache_free_oldest(void);
int cache_free_expired(void);
struct cacheentry *cache_search_entry(char *name, int qclass, int qtype);

/* The destructor for the cache entry */
void ht_cache_destructor(void *obj)
{
	struct cacheentry *cache = obj;

	free(cache->name);
	free(cache->answer);
	free(cache);
}

/* Add an entry in the cache hash table */
void cache_add_entry(struct forwardentry *p, byte *packet, int packet_size)
{
	struct cacheentry *cache;
	char key[HT_MAX_KEYSIZE], *k;
	int ret;
	size_t klen;

	/* If the cache is full try to free the expired entry,
	 * if there aren't free the oldest entry in access time */
	if (cache_count >= cache_max) {
		if (cache_free_expired() == 0)
			cache_free_oldest();
	}

	if ((cache = malloc(sizeof(struct cacheentry))) == NULL)
		goto oom1;

	/* fill the new entry */
	cache->name = malloc(strlen(p->name)+1);
	if (cache->name == NULL)
		goto oom2;
	strlcpy(cache->name, p->name, strlen(p->name)+1);
	cache->qtype = p->qtype;
	cache->qclass = p->qclass;
	cache->answer_size = packet_size;
	cache->answer = malloc(packet_size);
	if (cache->answer == NULL)
		goto oom3;
	memcpy(cache->answer, packet, packet_size);
	cache->ttl = cache_get_min_ttl(packet, packet_size);
	cache->creat_timestamp = cache->ttlupdate_timestamp =
		 cache->last_timestamp = get_sec();
	cache->hits = 0;

	klen = rr_to_key(key, HT_MAX_KEYSIZE, cache->name, cache->qtype,
		cache->qclass, 0);
	if ((k = malloc(klen)) == NULL)
		goto oom4;
	memcpy(k, key, klen);
	ret = ht_add(&cache_table, k, cache);
	if (ret != HT_OK)
		goto oom4;
	cache_count++;
	return;

oom4:	free(cache->answer);
oom3:	free(cache->name);
oom2:	free(cache);
oom1:	return;
}

/* Free the oldest element in the cache (oldest in access time) */
void cache_free_oldest(void)
{
	unsigned int index = 0, oldest_index = 0;
	int ret;
	struct cacheentry *oldest = NULL, *current;

	yakuns_assert(cache_table.used > 0);
	/* search in the cache table for the oldest entry,
	 * XXX: better to remove a random element? It's at least
	 * _much_ fater */
	while((ret = ht_get_byindex(&cache_table, index)) != -1) {
		if (ret == 0) {
			index++;
			continue;
		}
		current = ht_value(&cache_table, index);
		if (oldest == NULL ||
		    current->last_timestamp < oldest->last_timestamp)
		{
			oldest = current;
			oldest_index = index;
		}
		index++;
	}
	if (oldest) {
		ht_free(&cache_table, oldest_index);
		cache_count--;
	}
	return;
}

/* Free the expired elements in the cache table */
int cache_free_expired(void)
{
	unsigned int index = 0;
	int ret;
	struct cacheentry *current;
	time_t now = get_sec();
	int expired = 0;

	if (cache_table.used == 0 || opt_cachenoexpire)
		return 0;

	/* search in the cache table for expired entries */
	while((ret = ht_get_byindex(&cache_table, index)) != -1) {
		if (ret == 0) {
			index++;
			continue;
		}
		current = ht_value(&cache_table, index);
		if (current->creat_timestamp + current->ttl <= (unsigned)now) {
			ylog(VERB_HIG, "Expired cache entry %s %s %s\n",
				qtype_to_str(current->qtype),
				qclass_to_str(current->qclass),
				current->name);
			ht_free(&cache_table, index);
			cache_count--;
			expired++;
			if (cache_count == 0)
				break;
		}
		index++;
	}
	return expired;
}

struct cacheentry *cache_search_entry(char *name, int qclass, int qtype)
{
	char key[HT_MAX_KEYSIZE];
	int ret;
	unsigned int i;
	struct cacheentry *cache;
	time_t now = get_sec();

	rr_to_key(key, HT_MAX_KEYSIZE, name, qtype, qclass, 0);
        ret = ht_search(&cache_table, key, &i);
	if (ret == HT_FOUND) {
		cache = ht_value(&cache_table, i);
		/* Expired? Free the entry and return NULL */
		if (opt_cachenoexpire == 0 &&
		    cache->creat_timestamp + cache->ttl <= (unsigned)now) {
			ylog(VERB_HIG, "Expired cache entry %s %s %s\n",
				qtype_to_str(cache->qtype),
				qclass_to_str(cache->qclass),
				cache->name);
			ht_free(&cache_table, i);
			cache_count--;
			return NULL;
		}
		/* Adjust the access time and return the element */
		cache->last_timestamp = get_sec();
		return cache;
	}
	return NULL;
}

void cache_fix_ttl(struct cacheentry *cache)
{
	fix_ttl(cache->answer, cache->answer_size, cache->ttlupdate_timestamp,
						   get_sec());
	cache->ttlupdate_timestamp = get_sec();
}

void cache_shuffle(struct cacheentry *cache)
{
	dns_shuffle(cache->answer, cache->answer_size);
}

static u_int32_t cache_get_min_ttl(byte *packet, int packet_size)
{
	u_int32_t ttl = get_min_ttl(packet, packet_size);

	/* Adjust it */
	if (ttl < cache_minttl)
		ttl = cache_minttl;
	else if (ttl > cache_maxttl)
		ttl = cache_maxttl;
	return ttl;
}

void cache_init(void)
{
	ht_init(&cache_table);
        ht_set_hash(&cache_table, ht_dnskey_hash);
        ht_set_key_destructor(&cache_table, ht_destructor_free);
        ht_set_val_destructor(&cache_table, ht_cache_destructor);
        ht_set_key_compare(&cache_table, ht_dnskey_compare);
}
