/*
 * Windows Registry FUSE Filesystem
 *
 * Written by Jody Bruchon <jody@jodybruchon.com> 2014-04-20
 *
 * Licensed under GNU GPL v2. See LICENSE and README for details.
 *
 */

#define VER "0.1"
#define VERDATE "2014-04-20"

#define FUSE_USE_VERSION 28
#include <fuse.h>
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
/*** End sanity checks ***/

#if ENABLE_NKOFS_CACHE_STATS
#define CACHE_HIT 0
#define CACHE_MISS 1
#define HASH_HIT 2
#define HASH_MISS 3
#define HASH_FAIL 4
#endif /* NKOFS_CACHE_STATS */

/* Value type file extensions */
const char *ext[REG_MAX+1] = {
	"none", "sz", "esz", "bin", "dw", "dwbe", "lnk",
	"msz", "reslist", "fullres", "res_req", "qw",
};

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

/* Enable/disable logging */
#if ENABLE_LOGGING
#define LOG(...) fprintf(wd->log, __VA_ARGS__); fflush(wd->log)
#else
#define LOG(...)
#endif
#if ENABLE_DEBUG_LOGGING
#define DLOG(...) fprintf(wd->log, __VA_ARGS__); fflush(wd->log)
#else
#define DLOG(...)
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
	time_t start_time;  /* Benchmark program performance */
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


/* Function prototypes */

#if ENABLE_NKOFS_CACHE_STATS
void cache_stats(struct winregfs_data *, char);
#endif /* NKOFS_CACHE_STATS */

inline void slash_fix(char *);
inline hash_t cache_hash(const char *);
int get_path_nkofs(struct winregfs_data *, char *, struct nk_key **);
static int winregfs_getattr(const char *, struct stat *);
static int winregfs_readdir(const char *, void *, fuse_fill_dir_t, off_t, struct fuse_file_info *);
static int winregfs_open(const char *, struct fuse_file_info *);
static int winregfs_read(const char *, char *, size_t, off_t, struct fuse_file_info *);

static struct fuse_operations winregfs_oper = {
	.getattr	= winregfs_getattr,
	.readdir	= winregfs_readdir,
	.open		= winregfs_open,
	.read		= winregfs_read,
};
