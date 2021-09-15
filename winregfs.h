/*
 * Windows Registry FUSE Filesystem
 *
 * Copyright (C) 2014-2021 by Jody Bruchon <jody@jodybruchon.com>
 * See winregfs.c for license information
 */

#ifndef WINREGFS_H
#define WINREGFS_H

#include "version.h"

#ifndef FSCK_WINREGFS
#define FUSE_USE_VERSION 26
#include <fuse.h>
#endif

#include "jody_hash.h"
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
# if !NKOFS_CACHE_ITEMS
# error ENABLE_NKOFS_CACHE enabled; NKOFS_CACHE_ITEMS must be set and non-zero
# endif
#endif
#ifdef FSCK_WINREGFS
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
#define nk_cache_stats(a,b)
#endif /* NKOFS_CACHE_STATS */

/* Data structures */

struct winregfs_data {
	struct hive *hive;
	int ro;
#if ENABLE_LOGGING
	FILE *log;
#endif
#if ENABLE_NKOFS_CACHE
	/* Cache previous nkofs/path/key sets up to NKOFS_CACHE_ITEMS */
	int nk_cache_pos;
	char *nk_last_path[NKOFS_CACHE_ITEMS];
	int nk_last_nkofs[NKOFS_CACHE_ITEMS];
	struct nk_key *nk_last_key[NKOFS_CACHE_ITEMS];
	jodyhash_t nk_hash[NKOFS_CACHE_ITEMS];
# if ENABLE_NKOFS_CACHE_STATS
	int delay;  /* Cache log throttling interval */
	int nk_cache_miss;
	int nk_cache_hit;
	int nk_hash_miss;
	int nk_hash_hit;
	int nk_hash_fail;
# endif
# if ENABLE_THREADED
	pthread_mutex_t *lock;
# endif
#endif
};

/* Shortcut to pull winregfs_data structure into a function
   This MUST BE PLACED between variable declarations and code in ANY
   function that uses winregfs logging or data */
#define LOAD_WD() struct winregfs_data *wd; \
		  wd = fuse_get_context()->private_data;

/* Enable/disable logging
   We check wd for non-NULL before logging since wd may be unallocated
   during startup before fuse_main() */
#if ENABLE_LOGGING
# define LOG_IS_USED 1
# define LOG(...) if (wd) { \
			fprintf(wd->log, __VA_ARGS__); fflush(wd->log); \
		  } else printf(__VA_ARGS__);
# define LOAD_WD_LOGONLY() struct winregfs_data *wd; \
		  wd = fuse_get_context()->private_data;
#else
# define LOAD_WD_LOGONLY()
# if ENABLE_DEBUG_PRINTF
#  define LOG_IS_USED 1
#  define LOG(...) printf(__VA_ARGS__)
# else
#  define LOG(...)
# endif
#endif

/* Use DLOG for places where logging may be high-volume */
#if ENABLE_DEBUG_LOGGING
# define LOG_IS_USED 1
# define DLOG(...) if (wd) { \
			fprintf(wd->log, __VA_ARGS__); fflush(wd->log); \
		  } else printf(__VA_ARGS__);
#else
# if ENABLE_DEBUG_PRINTF
#  define LOG_IS_USED 1
#  define DLOG(...) printf(__VA_ARGS__);
# else
#  define DLOG(...)
# endif
#endif

#ifndef LOG_IS_USED
#define LOG_IS_USED 0
#endif

/* Threaded mode mutex */
#if ENABLE_THREADED
#define LOCK() pthread_mutex_lock(wd->lock)
#define UNLOCK() pthread_mutex_unlock(wd->lock)
#else
#define LOCK()
#define UNLOCK()
#endif

void invalidate_nk_cache(void);

#endif /* WINREGFS_H */
