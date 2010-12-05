/* An implementation of in-memory hash tables:
 * Copyright (c) 2000-2002 Salvatore Sanfilippo <antirez@invece.org>
 *
 * -- VERSION 2002.09.07 --
 *
 * COPYRIGHT AND PERMISSION NOTICE
 * -------------------------------
 *
 * Copyright (c) 2000 Salvatore Sanfilippo <antirez@invece.org>
 * Copyright (c) 2001 Salvatore Sanfilippo <antirez@invece.org>
 * Copyright (c) 2002 Salvatore Sanfilippo <antirez@invece.org>
 *
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, and/or sell copies of the Software, and to permit persons
 * to whom the Software is furnished to do so, provided that the above
 * copyright notice(s) and this permission notice appear in all copies of
 * the Software and that both the above copyright notice(s) and this
 * permission notice appear in supporting documentation.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT
 * OF THIRD PARTY RIGHTS. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * HOLDERS INCLUDED IN THIS NOTICE BE LIABLE FOR ANY CLAIM, OR ANY SPECIAL
 * INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Except as contained in this notice, the name of a copyright holder
 * shall not be used in advertising or otherwise to promote the sale, use
 * or other dealings in this Software without prior written authorization
 * of the copyright holder.
 *
 * OVERVIEW
 * --------
 *
 * AHT is an implementation of a dictionary with support for
 * INSERT, DELETE and SEARCH operations. It uses the hash table
 * as base data structure to provide almost constant times for
 * the three operations. AHT also automatically care about the
 * size of the current key-values set increasing the hash table
 * as needed.
 *
 * DESIGN PRINCIPLE
 * ----------------
 *
 * - AHT try to resist to attacker-induced worst-case behaviour
 *   trought the randomization of the hash-function. This is
 *   optional.
 *
 * - AHT takes care of the hash table expansion when needed.
 *   The hash table load ranges from 0 to 0.5, the hash table
 *   size is a power of two.
 *
 * - A simple implementation. The collisions resolution used
 *   is a simple linear probing, that takes advantage of
 *   the modern CPU caches, the low hash table max load and
 *   the use of a strong hash function provided with this library
 *   (ht_strong_hash), should mitigate the primary clustering
 *   enough. Experimental results shown that double hashing
 *   was a performance lost with common key types in modern
 *   CPUs.
 *
 * - Moderatly method oriented, it is possible to define the hash
 *   function, key/value destructors, key compare function, for a
 *   given hash table, but not with a per-element base.
 *
 * - Specialized slab allocator for the hash table element structure,
 *   useful when there are a number of INSERT/DELETE operations.
 *   It is compiled off by default.
 *
 * === WARNING ===
 * =    Before to use this library, think about the -fact- that the
 * =    worst case is O(N). Like for the quick sort algorithm, it may
 * =    be a bad idea to use this library in medical software, or other
 * =    software for wich the worst case should be taken in account
 * =    even if not likely to happen.
 * =    Good alternatives are red-black trees, and other trees with
 * =    a good worst-case behavior.
 * ===============
 *
 * HOW TO GET UP TO DATE CODE
 * --------------------------
 *
 * http://antirez.sed-consortium.com/software/aht.html
 *
 * TODO
 * ----
 *
 * - Write the documentation
 * - ht_copy() to copy an element between hash tables
 * - ht_dup() to duplicate an entire hash table
 * - ht_merge() to add the content of one hash table to another
 * - disk operations, the ability to save an hashtable from the
 *   memory to the disk and the reverse operation.
 *
 * Most of this features needs additional methods, like one
 * to copy an object, and should return an error if such methods
 * are not defined.
 *
 */

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "aht.h"

/* -------------------------- private prototypes ---------------------------- */
static int ht_expand_if_needed(struct hashtable *t);
static unsigned int next_power(unsigned int size);
static int ht_insert(struct hashtable *t, void *key, unsigned int *avail_index);

#ifdef AHT_USE_SLAB
static void slab_init(struct ht_cache *c);
static void slab_destroy(struct ht_cache *c);
static void *slab_get_obj(struct ht_cache *c);
static void slab_free_obj(struct ht_cache *c, void *ptr);
#endif /* AHT_USE_SLAB */

/* The special ht_free_element pointer is used to mark
 * a freed element in the hash table (note that the elements
 * neven used are just NULL pointers) */
static struct ht_ele *ht_free_element = (void*) -1;

/* -------------------------- hash functions -------------------------------- */
/* The djb hash function, that's under public domain */
u_int32_t djb_hash(unsigned char *buf, size_t len)
{
	u_int32_t h = 5381;
	while(len--)
		h = (h + (h << 5)) ^ *buf++;
	return h;
}

u_int32_t djb_hashR(unsigned char *buf, size_t len)
{
	u_int32_t h = 5381;
	buf += len-1;
	while(len--)
		h = (h + (h << 5)) ^ *buf--;
	return h;
}

/* Another trivial hash function */
#define ROT32R(x,n) (((x)>>n)|(x<<(32-n)))
u_int32_t trivial_hash(unsigned char *buf, size_t len)
{
	u_int32_t h = 0;
	while(len--) {
		h = h + *buf++;
		h = ROT32R(h, 3);
	}
	return h;
}

u_int32_t trivial_hashR(unsigned char *buf, size_t len)
{
	u_int32_t h = 0;
	buf += len-1;
	while(len--) {
		h = h + *buf--;
		h = ROT32R(h, 3);
	}
	return h;
}

/* A strong hash function that should be the default with this
 * hashtable implementation. Our hash tables does not support
 * double hashing for design: the idea is to avoid double
 * hashing and use a bit slower but very strong hash function like
 * this. This should provide quite good performances with
 * all the kinds of keys if you take the default max load of 50%.
 *
 * For more information see: http://burtleburtle.net/bob/hash/evahash.html */

/* The mixing step */
#define mix(a,b,c) \
{ \
  a=a-b;  a=a-c;  a=a^(c>>13); \
  b=b-c;  b=b-a;  b=b^(a<<8);  \
  c=c-a;  c=c-b;  c=c^(b>>13); \
  a=a-b;  a=a-c;  a=a^(c>>12); \
  b=b-c;  b=b-a;  b=b^(a<<16); \
  c=c-a;  c=c-b;  c=c^(b>>5);  \
  a=a-b;  a=a-c;  a=a^(c>>3);  \
  b=b-c;  b=b-a;  b=b^(a<<10); \
  c=c-a;  c=c-b;  c=c^(b>>15); \
}

/* The whole new hash function */
u_int32_t __ht_strong_hash(u_int8_t *k, u_int32_t length, u_int32_t initval)
{
	u_int32_t a,b,c;	/* the internal state */
	u_int32_t len;		/* how many key bytes still need mixing */

	/* Set up the internal state */
	len = length;
	a = b = 0x9e3779b9;  /* the golden ratio; an arbitrary value */
	c = initval;         /* variable initialization of internal state */

	/*---------------------------------------- handle most of the key */
	while (len >= 12)
	{
		a=a+(k[0]+((u_int32_t)k[1]<<8)+((u_int32_t)k[2]<<16)+
					       ((u_int32_t)k[3]<<24));
		b=b+(k[4]+((u_int32_t)k[5]<<8)+((u_int32_t)k[6]<<16)+
					       ((u_int32_t)k[7]<<24));
		c=c+(k[8]+((u_int32_t)k[9]<<8)+((u_int32_t)k[10]<<16)+
					       ((u_int32_t)k[11]<<24));
		mix(a,b,c);
		k = k+12; len = len-12;
	}

	/*------------------------------------- handle the last 11 bytes */
	c = c+length;
	switch(len)              /* all the case statements fall through */
	{
		case 11: c=c+((u_int32_t)k[10]<<24);
		case 10: c=c+((u_int32_t)k[9]<<16);
		case 9 : c=c+((u_int32_t)k[8]<<8);
		/* the first byte of c is reserved for the length */
		case 8 : b=b+((u_int32_t)k[7]<<24);
		case 7 : b=b+((u_int32_t)k[6]<<16);
		case 6 : b=b+((u_int32_t)k[5]<<8);
		case 5 : b=b+k[4];
		case 4 : a=a+((u_int32_t)k[3]<<24);
		case 3 : a=a+((u_int32_t)k[2]<<16);
		case 2 : a=a+((u_int32_t)k[1]<<8);
		case 1 : a=a+k[0];
		/* case 0: nothing left to add */
	}
	mix(a,b,c);
	/*-------------------------------------------- report the result */
	return c;
}

/* ----------------------------- API implementation ------------------------- */
/* Initialize the hash table */
int ht_init(struct hashtable *t)
{
	t->table = NULL;
	t->size = 0;
	t->sizemask = 0;
	t->used = 0;
	t->collisions = 0;
	t->hashf = NULL;
	t->key_destructor = ht_no_destructor;
	t->val_destructor = ht_no_destructor;
	t->key_compare = ht_compare_ptr;
#ifdef AHT_USE_SLAB
	t->cache = malloc(sizeof(struct ht_cache));
	if (!t->cache)
		return HT_NOMEM;
	slab_init(t->cache);
#endif
	return HT_OK;
}

/* Resize the table to the minimal size that contains all the elements */
int ht_resize(struct hashtable *t)
{
	int minimal = (t->used * 2)+1;

	if (minimal < HT_INITIAL_SIZE)
		minimal = HT_INITIAL_SIZE;
	return ht_expand(t, minimal);
}

/* Move an element accross hash tables */
int ht_move(struct hashtable *orig, struct hashtable *dest, unsigned int index)
{
	int ret;
	unsigned int new_index;

	/* If the element isn't in the table ht_search will store
	 * the index of the free ht_ele in the integer pointer by *index */
	ret = ht_insert(dest, orig->table[index]->key, &new_index);
	if (ret != HT_OK)
		return ret;

	/* Move the element */
	dest->table[new_index] = orig->table[index];
	orig->table[index] = ht_free_element;
	orig->used--;
	dest->used++;
	return HT_OK;
}

/* Expand or create the hashtable */
int ht_expand(struct hashtable *t, size_t size)
{
	struct hashtable n; /* the new hashtable */
	unsigned int realsize = next_power(size), i;

	/* the size is invalid if it is smaller than the number of
	 * elements already inside the hashtable */
	if (t->used >= size)
		return HT_INVALID;

	ht_init(&n);
	n.size = realsize;
	n.sizemask = realsize-1;
	n.table = malloc(realsize*sizeof(struct ht_ele*));
	if (n.table == NULL)
		return HT_NOMEM;
	/* Copy methods */
	n.hashf = t->hashf;
	n.key_destructor = t->key_destructor;
	n.val_destructor = t->val_destructor;
	n.key_compare= t->key_compare;
#ifdef AHT_USE_SLAB
	/* We need also to migrate the object cache to the new
	 * slab. We can just free the new and copy the old pointer */
	free(n.cache);
	n.cache = t->cache;
#endif /* AHT_USE_SLAB */

	/* Initialize all the pointers to NULL */
	memset(n.table, 0, realsize*sizeof(struct ht_ele*));

	/* Copy all the elements from the old to the new table:
	 * note that if the old hash table is empty t->size is zero,
	 * so ht_expand() acts like an ht_create() */
	n.used = t->used;
	for (i = 0; i < t->size && t->used > 0; i++) {
		if (t->table[i] != NULL && t->table[i] != ht_free_element) {
			u_int32_t h;

			/* Get the new element index: note that we
			 * know that there aren't freed elements in 'n' */
			h = n.hashf(t->table[i]->key) & n.sizemask;
			if (!n.table[h])
				goto move;
			n.collisions++;
			while(1) {
				h = (h+1) & n.sizemask;
				if (!n.table[h])
					break;
				n.collisions++;
			}
move:			/* Move the element */
			n.table[h] = t->table[i];
			t->used--;
		}
	}
	assert(t->used == 0);
	free(t->table);

	/* Remap the new hashtable in the old */
	*t = n;
	return HT_OK;
}

/* Add an element, discarding the old if the key already exists */
int ht_replace(struct hashtable *t, void *key, void *data)
{
	int ret;
	unsigned int index;

	/* Try to add the element */
	ret = ht_add(t, key, data);
	if (ret == HT_OK || ret != HT_BUSY)
		return ret;
	/* It already exists, get the index */
	ret = ht_search(t, key, &index);
	assert(ret == HT_FOUND);
	/* Remove the old */
	ret = ht_free(t, index);
	assert(ret == HT_OK);
	/* And add the new */
	return ht_add(t, key, data);
}

/* Add an element to the target hash table */
int ht_add(struct hashtable *t, void *key, void *data)
{
	int ret;
	unsigned int index;

	/* If the element isn't in the table ht_insert() will store
	 * the index of the free ht_ele in the integer pointer by *index */
	ret = ht_insert(t, key, &index);
	if (ret != HT_OK)
		return ret;

	/* Allocates the memory and stores key */
#ifdef AHT_USE_SLAB
	if ((t->table[index] = slab_get_obj(t->cache)) == NULL)
#else
	if ((t->table[index] = malloc(sizeof(struct ht_ele))) == NULL)
#endif /* AHT_USE_SLAB */
		return HT_NOMEM;
	/* Store the pointers */
	t->table[index]->key = key;
	t->table[index]->data = data;
	t->used++;
	return HT_OK;
}

/* search and remove an element */
int ht_rm(struct hashtable *t, void *key)
{
	int ret;
	unsigned int index;

	if ((ret = ht_search(t, key, &index)) != HT_FOUND)
		return ret;
	return ht_free(t, index);
}

/* Destroy an entire hash table */
int ht_destroy(struct hashtable *t)
{
	unsigned int i;
	struct hashtable copy = *t;

	/* Free all the elements */
	for (i = 0; i < t->size && t->used > 0; i++) {
		if (t->table[i] != NULL && t->table[i] != ht_free_element) {
			if (t->key_destructor)
				t->key_destructor(t->table[i]->key);
			if (t->val_destructor)
				t->val_destructor(t->table[i]->data);
#ifndef AHT_USE_SLAB
			free(t->table[i]);
#endif
			t->used--;
		}
	}
#ifdef AHT_USE_SLAB
	slab_destroy(t->cache);
#endif
	/* Free the table and the allocated cache structure */
	free(t->table);
#ifdef AHT_USE_SLAB
	free(t->cache);
#endif
	/* Re-initialize the table */
	ht_init(t);
	/* Restore methods */
	t->hashf = copy.hashf;
	t->key_destructor = copy.key_destructor;
	t->val_destructor = copy.val_destructor;
	t->key_compare = copy.key_compare;
	return HT_OK; /* It can't fail ht_destroy never fails */
}

/* Free an element in the hash table */
int ht_free(struct hashtable *t, unsigned int index)
{
	if (index >= t->size)
		return HT_IOVERFLOW; /* Index overflow */
	/* ht_free() calls against non-existent elements are ignored */
	if (t->table[index] != NULL && t->table[index] != ht_free_element) {
		/* release the key */
		if (t->key_destructor)
			t->key_destructor(t->table[index]->key);
		/* release the value */
		if (t->val_destructor)
			t->val_destructor(t->table[index]->data);
		/* free the element structure */
#ifdef AHT_USE_SLAB
		slab_free_obj(t->cache, t->table[index]);
#else
		free(t->table[index]);
#endif /* AHT_USE_SLAB */
		/* mark the element as freed */
		t->table[index] = ht_free_element;
		t->used--;
	}
	return HT_OK;
}

/* Search the element with the given key */
int ht_search(struct hashtable *t, void *key, unsigned int *found_index)
{
	int ret;
	u_int32_t h;

	/* Expand the hashtable if needed */
	if (t->size == 0) {
		if ((ret = ht_expand_if_needed(t)) != HT_OK)
			return ret;
	}

	/* Try using the first hash functions */
	h = t->hashf(key) & t->sizemask;
	/* this handles the removed elements */
	if (!t->table[h])
		return HT_NOTFOUND;
	if (t->table[h] != ht_free_element &&
	    t->key_compare(key, t->table[h]->key))
	{
		*found_index = h;
		return HT_FOUND;
	}

	while(1) {
		h = (h+1) & t->sizemask;
		/* this handles the removed elements */
		if (t->table[h] == ht_free_element)
			continue;
		if (!t->table[h])
			return HT_NOTFOUND;
		if (t->key_compare(key, t->table[h]->key)) {
			*found_index = h;
			return HT_FOUND;
		}
	}
}

/* This function is used to run the entire hash table,
 * it returns:
 * 1  if the element with the given index is valid
 * 0  if the element with the given index is empty or marked free
 * -1 if the element if out of the range */
int ht_get_byindex(struct hashtable *t, unsigned int index)
{
	if (index >= t->size)
		return -1;
	if (t->table[index] == NULL || t->table[index] == ht_free_element)
		return 0;
	return 1;
}

/* ------------------------- private functions ------------------------------ */

/* Expand the hash table if needed */
static int ht_expand_if_needed(struct hashtable *t)
{
	/* If the hash table is empty expand it to the intial size,
	 * if the table is half-full redobule its size. */
	if (t->size == 0)
		return ht_expand(t, HT_INITIAL_SIZE);
	if (t->size <= (t->used << 1))
		return ht_expand(t, t->size << 1);
	return HT_OK;
}

/* Our hash table capability is a power of two */
static unsigned int next_power(unsigned int size)
{
	unsigned int i = 256;

	if (size >= 2147483648U)
		return 2147483648U;
	while(1) {
		if (i >= size)
			return i;
		i *= 2;
	}
}

/* the insert function to add elements out of ht expansion */
static int ht_insert(struct hashtable *t, void *key, unsigned int *avail_index)
{
	int ret;
	u_int32_t h;

	/* Expand the hashtable if needed */
	if ((ret = ht_expand_if_needed(t)) != HT_OK)
		return ret;

	/* Try using the first hash functions */
	h = t->hashf(key) & t->sizemask;
	/* this handles the removed elements */
	if (!t->table[h] || t->table[h] == ht_free_element) {
		*avail_index = h;
		return HT_OK;
	}
	t->collisions++;
	if (t->key_compare(key, t->table[h]->key))
		return HT_BUSY;

	while(1) {
		h = (h+1) & t->sizemask;
		/* this handles the removed elements */
		if (!t->table[h] || t->table[h] == ht_free_element) {
			*avail_index = h;
			return HT_OK;
		}
		t->collisions++;
		if (t->key_compare(key, t->table[h]->key))
			return HT_BUSY;
	}
}

/* ------------------------- provided destructors --------------------------- */

/* destructor for heap allocated keys/values */
void ht_destructor_free(void *obj)
{
	free(obj);
}

/* ------------------------- provided comparators --------------------------- */

/* default key_compare method */
int ht_compare_ptr(void *key1, void *key2)
{
	return (key1 == key2);
}

/* key compare for nul-terminated strings */
int ht_compare_string(void *key1, void *key2)
{
	return (strcmp(key1, key2) == 0) ? 1 : 0;
}

/* -------------------- hash functions for common data types --------------- */

/* We make this global to allow hash function randomization,
 * as security measure against attacker-induced worst case behaviuor.
 *
 * Note that being H_i the strong hash function with init value of i
 * and H_i' the same hash function with init value of i' than:
 *
 * if H_i(StringOne) is equal to H_i(CollidingStringTwo)
 *
 *    it is NOT true that
 *
 *  H_i'(StringOne) is equal to H_i''(CollidingStringTwo)
 */
static u_int32_t strong_hash_init_val = 0xF937A21;

/* Set the secret initialization value. It should be set from
 * a secure PRNG like /dev/urandom at program initialization time */
void ht_set_strong_hash_init_val(u_int32_t secret)
{
	strong_hash_init_val = secret;
}

/* __ht_strong_hash wrapper that mix a user-provided initval
 * with the global strong_hash_init_val. __ht_strong_hash is
 * even exported directly. */
u_int32_t ht_strong_hash(u_int8_t *k, u_int32_t length, u_int32_t initval)
{
	return __ht_strong_hash(k, length, initval^strong_hash_init_val);
}

/* Hash function suitable for C strings and other data types using
 * a 0-byte as terminator */
u_int32_t ht_hash_string(void *key)
{
	return __ht_strong_hash(key, strlen(key), strong_hash_init_val);
}

/* ------------------------------- memory ----------------------------------- */

#ifdef AHT_USE_SLAB

#define SLAB_OBJFULSZ		((SLAB_OBJSZ)+(SLAB_PTRSZ))

/* minimum number of free elements to consider the slab not full */
#define SLAB_NOTFUL_THRE	32

/* get the slab pointer stored in the tail of the object */
#define SLAB_BY_PTR(ptr, slab) do { \
	void **p = (void**)((unsigned char*)ptr + SLAB_OBJSZ); \
	slab = *p; \
} while(0);

/* store the slab ptr in the tail of the object */
#define SLAB_STORE_PTR(obj, slab) do { \
	void **p = (void**)((unsigned char*)ptr + SLAB_OBJSZ); \
	*p = slab; \
} while(0)

#if 0	/* this works with unaligned data */
/* get the slab pointer stored in the tail of the object */
#define SLAB_BY_PTR(ptr, slab) do { \
	memcpy(&slab, ((unsigned char*)ptr)+SLAB_OBJSZ, sizeof(void*)); \
} while(0)

/* store the slab ptr in the tail of the object */
#define SLAB_STORE_PTR(ptr, slab) do { \
	memcpy(((unsigned char*)ptr)+SLAB_OBJSZ, &slab, sizeof(void*)); \
} while(0)
#endif

u_int8_t slab_free_list_init[SLAB_ELE] = {
0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 
0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0, 
0xef, 0xee, 0xed, 0xec, 0xeb, 0xea, 0xe9, 0xe8, 
0xe7, 0xe6, 0xe5, 0xe4, 0xe3, 0xe2, 0xe1, 0xe0, 
0xdf, 0xde, 0xdd, 0xdc, 0xdb, 0xda, 0xd9, 0xd8, 
0xd7, 0xd6, 0xd5, 0xd4, 0xd3, 0xd2, 0xd1, 0xd0, 
0xcf, 0xce, 0xcd, 0xcc, 0xcb, 0xca, 0xc9, 0xc8, 
0xc7, 0xc6, 0xc5, 0xc4, 0xc3, 0xc2, 0xc1, 0xc0, 
0xbf, 0xbe, 0xbd, 0xbc, 0xbb, 0xba, 0xb9, 0xb8, 
0xb7, 0xb6, 0xb5, 0xb4, 0xb3, 0xb2, 0xb1, 0xb0, 
0xaf, 0xae, 0xad, 0xac, 0xab, 0xaa, 0xa9, 0xa8, 
0xa7, 0xa6, 0xa5, 0xa4, 0xa3, 0xa2, 0xa1, 0xa0, 
0x9f, 0x9e, 0x9d, 0x9c, 0x9b, 0x9a, 0x99, 0x98, 
0x97, 0x96, 0x95, 0x94, 0x93, 0x92, 0x91, 0x90, 
0x8f, 0x8e, 0x8d, 0x8c, 0x8b, 0x8a, 0x89, 0x88, 
0x87, 0x86, 0x85, 0x84, 0x83, 0x82, 0x81, 0x80, 
0x7f, 0x7e, 0x7d, 0x7c, 0x7b, 0x7a, 0x79, 0x78, 
0x77, 0x76, 0x75, 0x74, 0x73, 0x72, 0x71, 0x70, 
0x6f, 0x6e, 0x6d, 0x6c, 0x6b, 0x6a, 0x69, 0x68, 
0x67, 0x66, 0x65, 0x64, 0x63, 0x62, 0x61, 0x60, 
0x5f, 0x5e, 0x5d, 0x5c, 0x5b, 0x5a, 0x59, 0x58, 
0x57, 0x56, 0x55, 0x54, 0x53, 0x52, 0x51, 0x50, 
0x4f, 0x4e, 0x4d, 0x4c, 0x4b, 0x4a, 0x49, 0x48, 
0x47, 0x46, 0x45, 0x44, 0x43, 0x42, 0x41, 0x40, 
0x3f, 0x3e, 0x3d, 0x3c, 0x3b, 0x3a, 0x39, 0x38, 
0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30, 
0x2f, 0x2e, 0x2d, 0x2c, 0x2b, 0x2a, 0x29, 0x28, 
0x27, 0x26, 0x25, 0x24, 0x23, 0x22, 0x21, 0x20, 
0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19, 0x18, 
0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10, 
0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 
0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00, 
};

static void slab_init(struct ht_cache *c)
{
	c->head = NULL;
	c->tail = NULL;
	c->slabs = 0;
}

static void slab_destroy(struct ht_cache *c)
{
	struct ht_slab *s = c->head, *t;

	while(s) {
		t = s->next;
		free(s);
		s = t;
	}
}

static void *slab_get_obj(struct ht_cache *c)
{
	struct ht_slab *slab = c->head;
	void *ptr;

	/* allocation */
	if (!slab || !slab->free) {
		slab = malloc(sizeof(struct ht_slab));
		if (!slab)
			return NULL;
		/* link on head */
		if (c->head)
			c->head->prev = slab;
		else
			c->tail = slab;
		slab->next = c->head;
		slab->prev = NULL;
		slab->free = SLAB_ELE;
		memcpy(slab->freelist, slab_free_list_init, SLAB_ELE);
		slab->parent = c;
		c->head = slab;
		c->slabs++;
	}
	/* get a free object */
	slab->free--;
	ptr = slab->mem + (SLAB_OBJFULSZ * slab->freelist[slab->free]);
	/* if this slab is now full put it on the tail */
	if (!slab->free && c->slabs > 1) {
		/* unlink from head */
		c->head = slab->next;
		c->head->prev = NULL;
		/* link on tail */
		c->tail->next = slab;
		slab->prev = c->tail;
		slab->next = NULL;
		c->tail = slab;
	}
	SLAB_STORE_PTR(ptr, slab);
	return ptr;
}

static void slab_free_obj(struct ht_cache *c, void *ptr)
{
	struct ht_slab *slab;

	/* Obtain the slab pointer from the object */
	SLAB_BY_PTR(ptr, slab);
	/* Update the free list and the free count */
	slab->freelist[slab->free] = (ptr - (void*)slab->mem) / SLAB_OBJFULSZ;
	slab->free++;
	/* move this slab to the head if it reached the waterlevel */
	if (slab->free == SLAB_NOTFUL_THRE && c->slabs > 1) {
		if (slab == c->head) return;
		/* unlink from middle or tail, we are not the head
		 * so we can assume slab->prev != NULL */
		slab->prev->next = slab->next;
		if (slab->next) {
			slab->next->prev = slab->prev;
		} else {
			c->tail = slab->prev;
		}
		/* put on the head */
		slab->prev = NULL;
		slab->next = c->head;
		c->head->prev = slab;
		c->head = slab;
		return;
	}
	/* if this slab is empty:
	 * 	1) if it's already the head, free it if the next is not full.
	 * 	2) if the current head is full move it on the head
	 * 	   else destroy it */
	if (slab->free == SLAB_ELE && c->slabs > 1) {
		if (slab == c->head) {
			if (!slab->next->free)
				return;
			/* unlink from head and free */
			c->head = slab->next;
			c->head->prev = NULL;
			c->slabs--;
			free(slab);
			return;
		}
		/* unlink the slab, we can assume slab->prev != NULL */
		slab->prev->next = slab->next;
		if (slab->next) {
			slab->next->prev = slab->prev;
		} else {
			c->tail = slab->prev;
		}
		/* the current head is not full? free this slab */
		if (c->head->free) {
			c->slabs--;
			free(slab);
			return;
		}
		/* the current head is full, move this slab to the head */
		slab->prev= NULL;
		slab->next = c->head;
		c->head->prev = slab;
		c->head = slab;
		return;
	}
}

#endif /* AHT_USE_SLAB */
