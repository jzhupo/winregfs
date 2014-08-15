/*
 * Windows Registry FUSE Filesystem
 *
 * Written by Jody Bruchon <jody@jodybruchon.com> 2014-04-20
 *
 * Licensed under GNU GPL v2. See LICENSE and README for details.
 *
 */

#ifndef _WINREGFS_H
#define _WINREGFS_H

#include "version.h"

#ifndef _FSCK_
#define FUSE_USE_VERSION 26
#include <fuse.h>
#endif

#include "config.h"

/*** Check config.h settings for sanity ***/
#if ENABLE_NKOFS_CACHE_STATS
# if !ENABLE_NKOFS_CACHE
# warning ENABLE_NKOFS_CACHE_STATS requires ENABLE_NKOFS_CACHE
# undef ENABLE_NKOFS_CACHE
# define ENABLE_NKOFS_CACHE 1
# endif
#endif
#if ENABLE_DEBUG_LOGGING
# if !ENABLE_LOGGING
# warning ENABLE_DEBUG_LOGGING requires ENABLE_LOGGING
# undef ENABLE_LOGGING
# define ENABLE_LOGGING 1
# endif
#endif
#if ENABLE_NKOFS_CACHE
# if !CACHE_ITEMS
# error ENABLE_NKOFS_CACHE enabled; CACHE_ITEMS must be set and non-zero
# endif
#endif
#ifdef _FSCK_
#undef ENABLE_LOGGING
#define ENABLE_LOGGING 0
#undef ENABLE_THREADED
#define ENABLE_THREADED 0
#endif
/*** End sanity checks ***/

#if ENABLE_NKOFS_CACHE_STATS
#define CACHE_HIT 0
#define CACHE_MISS 1
#define HASH_HIT 2
#define HASH_MISS 3
#define HASH_FAIL 4
#else
#define cache_stats(a,b)
#endif /* NKOFS_CACHE_STATS */

/* Set hash width from config file */
#if HASH == 64
typedef uint64_t hash_t;
#elif HASH == 32
typedef uint32_t hash_t;
#elif HASH == 16
typedef uint16_t hash_t;
#elif HASH == 8
typedef uint8_t hash_t;
#else
typedef uint_fast32_t hash_t;
#endif

/* Shortcut to pull winregfs_data structure into a function
   This MUST BE PLACED between variable declarations and code in ANY
   function that uses winregfs logging or data */
#define LOAD_WD() struct winregfs_data *wd; \
		  wd = fuse_get_context()->private_data;

/* Enable/disable logging
   We check wd for non-NULL before logging since wd may be unallocated
   during startup before fuse_main() */
#if ENABLE_LOGGING
#define LOG(...) if (wd) { \
			fprintf(wd->log, __VA_ARGS__); fflush(wd->log); \
		  } else printf(__VA_ARGS__);
#define LOAD_WD_LOGONLY() struct winregfs_data *wd; \
		  wd = fuse_get_context()->private_data;
#else
#define LOAD_WD_LOGONLY()
# if ENABLE_DEBUG_PRINTF
# define LOG(...) printf(__VA_ARGS__);
# else
# define LOG(...)
# endif
#endif

/* Use DLOG for places where logging may be high-volume */
#if ENABLE_DEBUG_LOGGING
#define DLOG(...) if (wd) { \
			fprintf(wd->log, __VA_ARGS__); fflush(wd->log); \
		  } else printf(__VA_ARGS__);
#else
# if ENABLE_DEBUG_PRINTF
# define DLOG(...) printf(__VA_ARGS__);
# else
# define DLOG(...)
# endif
#endif


/* Threaded mode mutex */
#if ENABLE_THREADED
#define LOCK() pthread_mutex_lock(wd->lock)
#define UNLOCK() pthread_mutex_unlock(wd->lock)
#else
#define LOCK()
#define UNLOCK()
#endif


/* Data structures */

struct winregfs_data {
	struct hive *hive;
	int ro;
#if ENABLE_LOGGING
	FILE *log;
#endif
#if ENABLE_NKOFS_CACHE
	/* Cache previous nkofs/path/key sets up to CACHE_ITEMS */
	int cache_pos;
	char *last_path[CACHE_ITEMS];
	int last_nkofs[CACHE_ITEMS];
	struct nk_key *last_key[CACHE_ITEMS];
	hash_t hash[CACHE_ITEMS];
# if ENABLE_NKOFS_CACHE_STATS
	int delay;  /* Cache log throttling interval */
	int cache_miss;
	int cache_hit;
	int hash_miss;
	int hash_hit;
	int hash_fail;
# endif
# if ENABLE_THREADED
	pthread_mutex_t *lock;
# endif
#endif
};

void invalidate_cache(void);

#endif /* _WINREGFS_H */
