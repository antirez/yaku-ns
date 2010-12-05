/* assert.h
 *
 * just the assert that uses the DNS server logging
 *
 * Copyright (C) 2000-2001 by Salvatore Sanfilippo
 * <antirez@invece.org>
 *
 * This code is under the GPL license version 2
 * See the COPYING file for more information
 */

#ifndef ENS_ASSERT_H
#define ENS_ASSERT_H

#ifdef NDEBUG

#define assert(expr)	do { } while(0)

#else /* !NDEBUG */

#define assert(x) \
do { \
	if ((x) == 0) { \
		ylog(VERB_FORCE, \
			"assert failed: %s is false in %s at line %d\n", \
			#x, __FILE__, __LINE__); \
		abort(); \
	} \
} while(0)

#endif /* !NDEBUG */

#endif /* ENS_ASSERT_H */
