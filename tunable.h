#ifndef __CONFIG_H
#define __CONFIG_H

/* This is the ENS's config.h file, you can change defaults and enable/disable
 * some feature here. If you trying to obtain binary size reduction you should
 * start commenting some ENS_* #define in this file. */

/* ------------ The version number follows the linux kernel way ------------- */
#define ENS_VERSION "0.1.6"

#if 0
#ifdef __i386__
#define PROFILING
#endif
#endif

/* ----------------------------- defaults ------------------------------------*/
/* All the following defines are just defaults that are overridable
 * using the command line options. See the README for more information.
 */
#define DNS_PORT                53
#define DNS_FORWARD_PORT        53
#define FORWARD_MAX_QUEUE       1000		/* 0 means disable forwarding */
#define FORWARD_TIMEOUT         50		/* 0 means disable timeout */
#define NEXT_SERVER_TIMEOUT     3
#define CACHE_MAX               5000		/* 0 means disable cache */
#define SAFEUSER                "nobody"
#define CONFIG_FILE             "/usr/local/yaku-ns/yaku-ns.conf"
#define YK_CORE_SIZE		2000		/* max core dump size */
#define CNAME_CHAIN_MAX		4		/* max lenght of cname chain
						   to follow in local lookup */

/* ---------------------------- fixed defines --------------------------------*/
#define MAX_FORWARD_SERVERS     10

/* ---------------------------- TTL related defines --------------------------*/
/* default time to live for local RRs */
#define TTL_LOCAL_DEFAULT       3600		/* 1h */
/* TTL_MAX/MIN is the max/min time to live in the cache for a response */
#define CACHE_MAX_TTL		86400		/* 1 day */
#define CACHE_MIN_TTL		0		/* 0 seconds */
/* time to live for errors */
#define TTL_ERR_FORMAT          0
#define TTL_ERR_FAILURE         0
#define TTL_ERR_NAME            60
#define TTL_ERR_NOTIMPLEMENTED  0
#define TTL_ERR_REFUSED         0

/* ---------------------------- Additional RRs -------------------------------*/
/* max number of additional RRs */
#define MAX_ADDRR 20

/* ---------------------------- Configuration --------------------------------*/
/* max number of tokens for line in config file and dynamic ENS protocol */
#define LINEARGS_MAX 64

/* ---------------------------- ACL ------------------------------------------*/
/* leave this untouched! 255.255.255.255$\0 is 17 bytes */
#define RULE_MAXSIZE 17

/* --------------------------- Scheduler -------------------------------------*/
#define ENS_AWAKE_TIME_SEC      1
#define ENS_AWAKE_TIME_USEC     0
#define SCHEDULE_SCHEDULER	1
#define SCHEDULE_CACHE_EXPIRE	(60*15)		/* 15m */
#define SCHEDULE_HASH_RESIZE	(60*60)		/* 1h */

#endif
