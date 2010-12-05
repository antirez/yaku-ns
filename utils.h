/* utils.h - useful macro and defines
 *
 * Copyright(C) 2001-2002 Salvatore Sanfilippo <antirez@invece.org>
 * All rights reserved.
 * See the LICENSE file for COPYRIGHT and PERMISSION notice */

/* $Id: utils.h,v 1.1 2003/09/26 14:56:56 antirez Exp $ */

#ifndef __UTILS_H
#define __UTILS_H

#include <stdlib.h> /* abort() */

/* NULL may be defined as just 0, this may not the same as (void*)0
 * for some arch. An example is a 64bit hard with 32bit int, and can
 * create problems with variadic functions.
 *
 * For variadic functions we use NULLPTR instead */
#ifndef NULLPTR /* This is hopefully not defined */
#define NULLPTR ((void*)0)
#endif

#ifndef TRUE
#define TRUE    1
#define FALSE   0
#endif

/* It seems in gcc < 3.0 there is no way to suppress only the
 * warning for unused function parameters when you use -W.
 * This macro is better than -Wno-unused. We want all the
 * other unused warnings */
#define ARG_UNUSED(a) ((void) a);

#ifndef MIN
#define MIN(x,y)        ((x)<(y)?(x):(y))
#endif
#ifndef MAX
#define MAX(x,y)        ((x)>(y)?(x):(y))
#endif

#ifdef NDEBUG

#define yakuns_assert(expr)	do { } while(0)

#else /* !NDEBUG */

#define yakuns_assert(x) \
do { \
	if ((x) == 0) { \
		ylog(VERB_FORCE, \
			"assert failed: %s is false in %s at line %d\n", \
			#x, __FILE__, __LINE__); \
		abort(); \
	} \
} while(0)

#endif /* !NDEBUG */

#endif /* __UTILS_H */
