/*
 * Windows Registry FUSE Filesystem
 *
 * Copyright (C) 2014, 2015 Jody Bruchon <jody@jodybruchon.com>
 *
 * Mounts a Windows registry hive file as a filesystem using FUSE
 * Registry keys become directories and values become files
 * Value files have an extension based on the value type
 * (blah.sz = REG_SZ string; blah.dw = REG_DWORD 32-bit number)
 *
 * Licensed under GNU GPL v2. See LICENSE and README for details.
 *
 * TODO:
 *
 * * Fix 8 KiB file write limit issue (may really be in ntreg.c)
 *   - For now an error is issued on attempts to write >8192 bytes
 *     since there are extremely few values that contain this much
 *     data; the XP compatibility shim cache is pretty much the
 *     only value of such a size (all others are <6000 bytes)
 *
 * * Allow arbitrary value types using a hexadecimal extension
 *   (used in SAM and some MS Click-to-Run registry keys)
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libgen.h>
#include <pthread.h>
#include "ntreg.h"
#include "jody_hash.h"
#include "winregfs.h"

/* Avoid str[n]cmp calls by doing this simple check directly */
#define PATH_IS_ROOT(a) (a[0] == '/' && a[1] == '\0')

/* Use Jody's block hash algorithm for the cache */
#define cache_hash(a) jody_block_hash((hash_t *)a, 0, strlen(a))

/* Value type file extensions */
const char *ext[REG_MAX + 1] = {
	"none", "sz", "esz", "bin", "dw", "dwbe", "lnk",
	"msz", "reslist", "fullres", "res_req", "qw", NULL
};

const char slash[] = "_SLASH_";
const int ss = sizeof(slash) - 1;


/*** Non-FUSE helper functions ***/

/* Return offset to the first non-hexadecimal char in string */
static int find_nonhex(const char * const restrict string, int len)
{
	unsigned char q;
	int offset;

	if (*string == 0) return -1;
	for(offset = 0; offset < len; offset++) {
		if (*(string + offset) == 0) return offset;
		q = *(string + offset) - 48;  /* ASCII 0-9 to real 0-9 */
		if (q > 48) q -= 39;
		if (q < 0 || q > 15) return offset;
	}
	return -1;
}


/* Convert hex string to integer */
static int convert_hex(const char * const restrict string,
		uint64_t * const restrict dest, int len)
{
	unsigned char q;
	int offset;

	*dest = 0;

	if (*string == 0) return -1;
	for(offset = 0; offset < len; offset++) {
		if (*(string + offset) == 0) return 0;
		*dest <<= 4;  /* Shift for each character processed */
		q = *(string + offset) - 48;  /* ASCII 0-9 to real 0-9 */
		if (q > 48) q -= 39;
		if (q < 0 || q > 15) return -1;
		*dest += q;
	}
	return 0;
}


/* Convert value to hex string, return string length */
static int bytes2hex(char * const restrict string,
		const void * const restrict data, const int bytes)
{
	int i, j = 0;
	unsigned char c;

	for(i = bytes - 1; i >= 0; i--) {
		c = *((char *)data + i);
		string[j] = (c >> 4) + 48;
		if (string[j] > 57) string[j] += 39;
		j++;
		string[j] = (c & 15) + 48;
		if (string[j] > 57) string[j] += 39;
		j++;
	}
	string[j] = '\n'; j++;
	string[j] = '\0';
	return (bytes << 1) + 2;
}

/* Remove extension and return numeric value for value type */
static int process_ext(char * const node)
{
	char * restrict str_ext;
	int i = 0;

	str_ext = strrchr(node, '.');
	/* Check for no-extension case */
	if (str_ext == NULL) return -1;
	*str_ext = '\0';
	str_ext++;
	for (; i < REG_MAX; i++) {
		if (!strncasecmp(str_ext, ext[i], 8)) return i;
	}
	return -1;
}


/* Add the type extension to the registry value name */
static inline int add_val_ext(char * const restrict filename,
		const struct vex_data * const restrict vex)
{
	LOAD_WD_LOGONLY();

	if (vex->type > REG_MAX) {
		LOG("add_val_ext: error: value type out of range: %s\n", filename);
		return 1;
	}
	strncpy(filename, vex->name, ABSPATHLEN);
	strncat(filename, ".", ABSPATHLEN);
	strncat(filename, ext[vex->type], ABSPATHLEN);
	return 0;
}


/* Convert slashes to backslashes */
static inline void slash_fix(char * const restrict path)
{
	int i;

	for (i = strlen(path); i >= 0; i--) {
		if (path[i] == '/') path[i] = '\\';
	}
}


/* Forward slashes cannot appear in pathname components */
static int escape_fwdslash(char * const path)
{
	int pos = 0;
	const char *p;
	char *q;
	char temp[ABSPATHLEN];

	LOAD_WD_LOGONLY();

	/* Avoid likely unnecessary work */
	if (!strchr(path, '/')) return 0;

	p = path;
	q = temp;
	for (; pos < ABSPATHLEN; pos++) {
		if (*p == '/') {
			strncpy(q, slash, ss);
			q += (ss - 1);
			pos = (pos + ss - 2);
		} else *q = *p;
		if (*p == '\0') break;
		q++; p++;
	}
	if (pos == ABSPATHLEN) {
		LOG("escape_fwdslash: maximum path length reached\n");
		return -ENAMETOOLONG;
	}
	strncpy(path, temp, ABSPATHLEN);
	return 0;
}


/* Reverse escape_fwdslash */
static int unescape_fwdslash(char *path)
{
	int pos = 0;
	const char *p;
	char *q;
	char temp[ABSPATHLEN];

	LOAD_WD_LOGONLY();

	/* Avoid likely unnecessary work */
	if (!strchr(path, slash[0])) return 0;

	p = path;
	q = temp;
	for (; pos < ABSPATHLEN; pos++) {
		if (!strncmp(p, slash, ss)) {
			*q = '/';
			p += (ss - 1);
			pos += (ss - 1);
		} else *q = *p;
		if (*p == '\0') break;
		q++; p++;
	}
	if (pos == ABSPATHLEN) {
		LOG("unescape_fwdslash: maximum path length reached\n");
		return -ENAMETOOLONG;
	}
	strncpy(path, temp, ABSPATHLEN);
	return 0;
}


#if ENABLE_NKOFS_CACHE_STATS
# if ENABLE_LOGGING
/* Log current cache stats every 100th cache event */
static void log_cache_stats(struct winregfs_data * const restrict wd)
{
	float c, h;

	/* c, h are checked to prevent divide by zero errors */
	if (wd->delay--) return;
	wd->delay = 100;
	c = wd->cache_miss + wd->cache_hit;
	h = wd->hash_miss + wd->hash_hit;
	LOG("cache: %d miss, %d hit (%3.2f%%); ",
			wd->cache_miss, wd->cache_hit,
			((wd->cache_hit * 100) / ((c>0) ? c : 1)));
	LOG("hash: %d miss, %d hit (%3.2f%%), %d fail (%3.2f%%)\n",
			wd->hash_miss, wd->hash_hit,
			((wd->hash_hit * 100) / ((h>0) ? h : 1)),
			wd->hash_fail,
			((wd->hash_fail * 100) / ((h>0) ? h : 1)));
}
# endif


/* Collect information on NK offset cache success/failure */
static inline void cache_stats(struct winregfs_data * const restrict wd,
		char hit)
{
	switch (hit) {
	case CACHE_HIT:
		wd->cache_hit++;
		break;
	case CACHE_MISS:
		wd->cache_miss++;
		break;
	case HASH_HIT:
		wd->hash_hit++;
		break;
	case HASH_MISS:
		wd->hash_miss++;
		break;
	case HASH_FAIL:
		wd->hash_fail++;
		break;
	}
# if ENABLE_LOGGING
	log_cache_stats(wd);
# endif
}
#endif /* NKOFS_CACHE_STATS */


/* Clear all cache elements (used when hive buffer is invalidated */
void invalidate_cache(void)
{
	int i;
	LOAD_WD();

	DLOG("winregfs cache invalidated\n");
	LOCK();
	for(i=0; i < CACHE_ITEMS; i++) wd->hash[i] = '\0';
	UNLOCK();
	return;
}


/* Caching offset fetcher. If update_cache is nonzero, the
 * function call will refresh the cache entry for the path
 * and stop (useful for things that modify directories)
 */
static int get_path_nkofs(struct winregfs_data * const restrict wd,
		const char * const restrict keypath,
		struct nk_key ** const key, int update_cache)
{
	int nkofs;

#if ENABLE_NKOFS_CACHE
	int i;
	hash_t hash;

	/* Check the cached path to avoid extra traversals */
	hash = cache_hash(keypath);

	LOCK();

	/* Work backwards in the hash cache ring until we come back
	 * where we started or encounter a zeroed (non-existent) hash */
	i = wd->cache_pos;
	while (1) {
		if (!wd->hash[i]) break;  /* 0 = end of recorded hashes */
		if (wd->hash[i] == hash) {
			cache_stats(wd, HASH_HIT);
			if (!strncasecmp(wd->last_path[i], keypath, ABSPATHLEN)) {
				if (!update_cache) {
					nkofs = wd->last_nkofs[i];
					*key = wd->last_key[i];
					cache_stats(wd, CACHE_HIT);
					UNLOCK();
					return nkofs;
				} else {
					nkofs = trav_path(wd->hive, 0, keypath, TPF_NK_EXACT);
					if (!nkofs) {
						LOG("get_path_nkofs: trav_path failed: %s\n", keypath);
						return 0;
					}
					nkofs += 4;
					wd->last_key[i] = (struct nk_key *)(wd->hive->buffer + nkofs);
					wd->last_nkofs[i] = nkofs;
					UNLOCK();
					return nkofs;
				}
			} else cache_stats(wd, HASH_FAIL);
		} else cache_stats(wd, HASH_MISS);
		if (update_cache) return 0;
		/* If we've hit item 0, return the cache ring position to the end of the ring */
		if (!i) i = CACHE_ITEMS;
		i--;
		if (i == wd->cache_pos) break;
	}

	UNLOCK();

	cache_stats(wd, CACHE_MISS);
#endif  /* NKOFS_CACHE */

	/* Cached path didn't match (or cache disabled), traverse and get offset */
	nkofs = trav_path(wd->hive, 0, keypath, TPF_NK_EXACT);
	if (!nkofs) {
		LOG("get_path_nkofs: trav_path failed: %s\n", keypath);
		return 0;
	}
	nkofs += 4;

	*key = (struct nk_key *)(wd->hive->buffer + nkofs);

#if ENABLE_NKOFS_CACHE
	/* Increment cache ring position, place new cache item */
	LOCK();

	if (++wd->cache_pos >= CACHE_ITEMS) wd->cache_pos = 0;
	strncpy(wd->last_path[wd->cache_pos], keypath, ABSPATHLEN);
	wd->last_nkofs[wd->cache_pos] = nkofs;
	wd->last_key[wd->cache_pos] = *key;
	wd->hash[wd->cache_pos] = cache_hash(keypath);

	UNLOCK();
#endif
	return nkofs;
}


/* Converts a path to the required formats for keypath/nodepath usage */
static inline int sanitize_path(const char * const restrict path,
		char * const restrict keypath, char * const restrict node)
{
	char temp[ABSPATHLEN];

	strncpy(keypath, path, ABSPATHLEN);
	strncpy(temp, path, ABSPATHLEN);
	dirname(keypath);   /* need to read the root key */
	strncpy(node, basename(temp), ABSPATHLEN);
	slash_fix(keypath);
	unescape_fwdslash(node);
	unescape_fwdslash(keypath);
	/* DLOG("sanitize_path: path %s, keypath %s, node %s\n", path, keypath, node); */
	return 0;
}
/*** End helper functions ***/


/*** FUSE functions ***/

/* Check if access to a particular file is allowed */
static int winregfs_access(const char * const restrict path, int mode)
{
	struct nk_key *key;
	int nkofs;
	struct ex_data ex;
	struct vex_data vex;
	int count = 0, countri = 0;
	char filename[ABSPATHLEN];
	char keypath[ABSPATHLEN];
	char node[ABSPATHLEN];

	LOAD_WD();

	DLOG("access: %s (%d)\n", path, mode);

	/* Read-only support (possible future feature) */
/*	if (mode & W_OK) {
		LOG("access: write requested for read-only filesystem\n");
		errno = EROFS;
		return -1;
	} */

	if (PATH_IS_ROOT(path)) return 0;
	sanitize_path(path, keypath, node);

	nkofs = get_path_nkofs(wd, keypath, &key, 0);
	if (!nkofs) {
		LOG("access: no offset: %s\n", keypath);
		return -ENOENT;
	}

	if (key->no_subkeys) {
		while (ex_next_n(wd->hive, nkofs, &count, &countri, &ex) > 0) {
			if (!strncasecmp(node, ex.name, ABSPATHLEN)) {
				DLOG("access: ex_n: %p size %d c %d cri %d\n",
						path, ex.nk->no_subkeys, count, countri);
				DLOG("access: directory OK: %s\n", node);
				free(ex.name);
				return 0;
			} else free(ex.name);
		}
	}

	count = 0;
	if (key->no_values) {
		while (ex_next_v(wd->hive, nkofs, &count, &vex) > 0) {
			if (strlen(vex.name) == 0) strncpy(filename, "@.sz", 5);
			else add_val_ext(filename, &vex);
			free(vex.name);
			if (!strncasecmp(node, filename, ABSPATHLEN)) {
				if (!(mode & X_OK)) {
					DLOG("access: OK: ex_v: nkofs %x vkofs %x size %d c %d\n",
							nkofs, vex.vkoffs, vex.size, count);
					return 0;
				} else {
					DLOG("access: exec not allowed: ex_v: nkofs %x vkofs %x size %d c %d\n",
							nkofs, vex.vkoffs, vex.size, count);
					return -EACCES;
				}
			}
		}
	}
	LOG("access: not found: %s\n", path);
	return -ENOENT;
}


/* Get file attributes; size is adjusted for conversions we perform transparently */
static int winregfs_getattr(const char * const restrict path,
		struct stat * const restrict stbuf)
{
	struct nk_key *key;
	int nkofs;
	struct ex_data ex;
	struct vex_data vex;
	int count = 0, countri = 0;
	char filename[ABSPATHLEN];
	char keypath[ABSPATHLEN];
	char node[ABSPATHLEN];
	char check1[ABSPATHLEN];
	char check2[ABSPATHLEN];
	char *token;
	int attrmask = 0777;

	LOAD_WD();

	DLOG("getattr: %s\n", path);

	if (wd->ro) attrmask = 0555;

	if (PATH_IS_ROOT(path)) {
		stbuf->st_mode = S_IFDIR | (0777 & attrmask);
		stbuf->st_nlink = 2;
		stbuf->st_size = 1;
		return 0;
	}
	sanitize_path(path, keypath, node);

	memset(stbuf, 0, sizeof(struct stat));

	nkofs = get_path_nkofs(wd, keypath, &key, 0);
	if (!nkofs) {
		LOG("getattr: no offset: %s\n", keypath);
		return -ENOENT;
	}

	DLOG("getattr: key->no_subkeys = %d\n", key->no_subkeys);
	if (key->no_subkeys) {
		while (ex_next_n(wd->hive, nkofs, &count, &countri, &ex) > 0) {
			if (!strncasecmp(node, ex.name, ABSPATHLEN)) {
				stbuf->st_mode = S_IFDIR | (0777 & attrmask);
				stbuf->st_nlink = 2;
				stbuf->st_size = ex.nk->no_subkeys;
				DLOG("getattr: ex_n: %s size %d c %d cri %d\n",
						path, ex.nk->no_subkeys, count, countri);
				free(ex.name);
				return 0;
			} else free(ex.name);
		}
	}

	count = 0;
	DLOG("getattr: key->no_values = %d\n", key->no_values);
	if (key->no_values) {
		while (ex_next_v(wd->hive, nkofs, &count, &vex) > 0) {
			if (strlen(vex.name) == 0) strncpy(filename, "@.sz", 5);
			else add_val_ext(filename, &vex);

			/* Wildcard accesses with no extension */
			if (!strrchr(node, '.')) {
				strncpy(check1, node, ABSPATHLEN);
				strncpy(check2, filename, ABSPATHLEN);
				token = strrchr(check2, '.');
				*token = '\0';
				if (!strncasecmp(check1, check2, ABSPATHLEN)) {
					LOG("getattr: wildcard found for %s\n", path);
					goto getattr_wildcard;
				} else {
					free(vex.name);
					continue;
				}
			}

			if (!strncasecmp(node, filename, ABSPATHLEN)) {
getattr_wildcard:
				stbuf->st_mode = S_IFREG | (0666 & attrmask);
				stbuf->st_nlink = 1;
				switch(vex.type) {
				case REG_QWORD:
					stbuf->st_size = 17;
					break;
				case REG_DWORD:
					stbuf->st_size = 9;
					break;
				case REG_SZ:
				case REG_EXPAND_SZ:
				case REG_MULTI_SZ:
					stbuf->st_size = vex.size >> 1;
					break;
				default:
					stbuf->st_size = vex.size;
				}
				DLOG("getattr: ex_v: nkofs %x vkofs %x size %d c %d\n",
						nkofs, vex.vkoffs, vex.size, count);
				return 0;
			}

			/* Prevent creation of conflicting files */
			strncpy(check1, node, ABSPATHLEN);
			token = strrchr(check1, '.');
			*token = '\0';
			strncpy(check2, filename, ABSPATHLEN);
			token = strrchr(check2, '.');
			*token = '\0';
			if (!strncasecmp(check1, check2, ABSPATHLEN)) {
				stbuf->st_mode = S_IFREG | 0000;
				stbuf->st_nlink = 1;
				stbuf->st_size = 0;
				DLOG("getattr: blocking file %s\n", path);
				return 0;
			}
			free(vex.name);
		}
	} else DLOG("getattr: no values for key: %p\n", (void *)key);
	LOG("getattr: not found: %s\n", path);
	return -ENOENT;
}


static int winregfs_readdir(const char * const restrict path,
		void *buf, fuse_fill_dir_t filler,
		off_t offset, struct fuse_file_info *fi)
{
	struct nk_key *key;
	int nkofs;
	struct ex_data ex;
	struct vex_data vex;
	int count = 0, countri = 0;
	char filename[ABSPATHLEN];
	char keypath[ABSPATHLEN];

	LOAD_WD();

	DLOG("readdir: %s  (+%d)\n", path, (int)offset);

	strncpy(keypath, path, ABSPATHLEN);
	slash_fix(keypath);
	unescape_fwdslash(keypath);

	nkofs = get_path_nkofs(wd, keypath, &key, 0);
	if (!nkofs) {
		LOG("readdir: get_path_nkofs failed: %s\n", keypath);
		return -ENOENT;
	}

	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);

	DLOG("readdir: key->no_subkeys = %d\n", key->no_subkeys);
	if (key->no_subkeys) {
		while (ex_next_n(wd->hive, nkofs, &count, &countri, &ex) > 0) {
			DLOG("readdir: n_filler: %s\n", ex.name);
			strncpy(filename, ex.name, ABSPATHLEN);
			free(ex.name);
			escape_fwdslash(filename);
			filler(buf, filename, NULL, 0);
		}
	}

	count = 0;
	DLOG("readdir: key->no_values = %d\n", key->no_values);
	if (key->no_values) {
		while (ex_next_v(wd->hive, nkofs, &count, &vex) > 0) {
			if (strlen(vex.name) == 0) {
				strncpy(filename, "@.sz", 5);
				DLOG("readdir: v_filler: %s\n", filename);
				filler(buf, filename, NULL, 0);
				free(vex.name);
			} else {
				if (!add_val_ext(filename, &vex)) {
					free(vex.name);
					escape_fwdslash(filename);
					DLOG("readdir: v_filler: %s\n", filename);
					filler(buf, filename, NULL, 0);
				} else {
					free(vex.name);
					LOG("readdir: error reading %s/%s\n", path, filename);
				}
			}
		}
	}
	return 0;
}


/* This really doesn't do anything now, but in the future we should
 * implement a proper open/write/release cycle and proper locking.
 * The chances of this code NEEDING this are very slim. Most users
 * are likely to access data in a very serialized manner.
 */
static int winregfs_open(const char * const restrict path,
		struct fuse_file_info *fi)
{
	struct nk_key *key;
	int nkofs;
	struct ex_data ex;
	struct vex_data vex;
	int count = 0, countri = 0;
	char filename[ABSPATHLEN];
	char keypath[ABSPATHLEN];
	char node[ABSPATHLEN];
	char check1[ABSPATHLEN];
	char check2[ABSPATHLEN];
	char *token;

	LOAD_WD();

	DLOG("open: %s\n", path);

	/* Read-only support (possible future feature) */
/*	if ((fi->flags & 3) != O_RDONLY) {
		LOG("open: Read-only: %s\n", path);
		return -EACCES;
	} */

	if (PATH_IS_ROOT(path)) {
		LOG("open: Is a directory: %s\n", path);
		return -EISDIR;
	}
	sanitize_path(path, keypath, node);

	nkofs = get_path_nkofs(wd, keypath, &key, 0);
	if (!nkofs) {
		LOG("open: get_path_nkofs failed: %s\n", keypath);
		return -ENOENT;
	}

	if (key->no_subkeys) {
		while (ex_next_n(wd->hive, nkofs, &count, &countri, &ex) > 0) {
			if (!strncasecmp(node, ex.name, ABSPATHLEN)) {  /* remove leading slash */
				LOG("open: Is a directory: %s\n", node);
				free(ex.name);
				return -EISDIR;
			} else free(ex.name);
		}
	}

	count = 0;
	if (key->no_values) {
		while (ex_next_v(wd->hive, nkofs, &count, &vex) > 0) {
			if (strlen(vex.name) == 0) strncpy(filename, "@.sz", 5);
			else add_val_ext(filename, &vex);
			free(vex.name);

			/* Wildcard accesses with no extension */
			if (!strrchr(node, '.')) {
				strncpy(check1, node, ABSPATHLEN);
				strncpy(check2, filename, ABSPATHLEN);
				token = strrchr(check2, '.');
				*token = '\0';
				if (!strncasecmp(check1, check2, ABSPATHLEN)) {
					LOG("open: wildcard found for %s\n", path);
					return 0;
				} else continue;
			}
			if (!strncasecmp(node, filename, ABSPATHLEN)) return 0;
		}
	}
	LOG("open: No such file or directory for %s\n", path);
	return -ENOENT;
}


static int winregfs_read(const char * const restrict path,
		char * const restrict buf, size_t size,
		off_t offset, struct fuse_file_info *fi)
{
	int nkofs;
	char filename[ABSPATHLEN];
	char node[ABSPATHLEN];
	char keypath[ABSPATHLEN];

	struct nk_key *key;
	void *data;
	size_t len;
	int i, type, count;
	int used_string = 0;  /* 1 if string should be freed */
	char *string = NULL;
	char dqw[18];  /* DWORD/QWORD ASCII hex string */
	struct keyval *kv = NULL;
	struct vex_data vex;

	LOAD_WD();

	DLOG("read: %s (%d + %d)\n", path, (int)size, (int)offset);

	sanitize_path(path, keypath, node);

	nkofs = get_path_nkofs(wd, keypath, &key, 0);
	if (!nkofs) {
		LOG("read: get_path_nkofs failed: %s\n", keypath);
		return -ENOENT;
	}

	/* Extract type information, remove extension from name */
	if (process_ext(node) < 0) {
		count = 0;
		if (key->no_values) {
			while (ex_next_v(wd->hive, nkofs, &count, &vex) > 0) {
				if (strlen(vex.name) == 0) strncpy(filename, "@", 2);
				else strncpy(filename, vex.name, ABSPATHLEN);
				free(vex.name);
				if (!strncasecmp(node, filename, ABSPATHLEN)) goto read_wildcard;
			}
		}
		LOG("read: invalid type extension: %s\n", path);
		return -EINVAL;
	}
read_wildcard:
	type = get_val_type(wd->hive, nkofs, node, TPF_VK_EXACT);
	if (type == -1) {
		LOG("read: No such value '%s'\n", node);
		return -EINVAL;
	}

	len = get_val_len(wd->hive, nkofs, node, TPF_VK_EXACT);
	if (len < 0) {
		if (*node == '\0') strncpy(node, "@", 2);
		LOG("read: Value not readable: '%s'\n", node);
		return -EINVAL;
	}

	kv = get_val2buf(wd->hive, NULL, nkofs, node, 0, TPF_VK_EXACT);
	if (!kv) {
		if (*node == '\0') strncpy(node, "@", 2);
		LOG("read: Can't read value data for '%s'\n", node);
		return -EINVAL;
	}
	data = (void *)(kv->data);

	switch (type) {
	case REG_SZ:
	case REG_EXPAND_SZ:
	case REG_MULTI_SZ:
		if (!len) break;
		/* UTF-16 to ASCII, nulls to newlines */
		string = string_regw2prog(data, len);
		for (i = 0; i < (len >> 1) - 1; i++) {
			if (string[i] == 0) string[i] = '\n';
			if (type == REG_SZ) break;
		}
		len = strlen(string) + 1;
		string[len - 1] = '\n';
		used_string = 1;
		break;
	case REG_QWORD:
		len = bytes2hex(dqw, data, 8);
		string = dqw;
		break;
	case REG_DWORD:
		len = bytes2hex(dqw, data, 4);
		string = dqw;
		break;
	default:
		LOG("read: Unknown type %d, treating as REG_BINARY\n", type);
	case REG_BINARY:
		string = data;
		break;
	}

	if (offset < len) {
		if (offset + size > len) size = len - offset;
		memcpy(buf, string + offset, size);
	} else size = 0;

	if (used_string) free(string);
	free(kv->data); free(kv);
	return size;
}


/* This function makes it painfully clear how ugly dealing with the
 * registry can be. REG_MULTI_SZ data types are the worst thing ever
 * designed and a special place in Hell exists with that data type.
 *
 * In the future, this function has the potential to become more
 * efficient if the "read-to-write" behavior could be eliminated.
 * Right now, any write at an offset other than zero will require
 * reading the existing value into the buffer, updating it, then
 * writing it back, which is grossly inefficient but is also the only
 * way to do this easily (and it's still reasonably quick too.)
 *
 * I wrote this entire program with just read-only support in about
 * two days, but THIS function single-handedly ate three days of my
 * life for testing and debugging...and it's still not where I want
 * it to be.
 *
 * Writes are limited to 8192 bytes maximum because somewhere between
 * here and ntreg.c we're losing the data. ntreg will allocate all the
 * needed blocks and fill with zeros, and 8192 bytes of data will be
 * placed, followed by zeroes until the end. Since the chances of ever
 * needing to write such a large value size are very slim, I decided
 * to cap writes at 8192 bytes and worry about this much later in the
 * future.
 */
static int winregfs_write(const char * const restrict path,
		const char * const restrict buf,
		size_t size, off_t offset, struct fuse_file_info *fi)
{
	int nkofs;
	char node[ABSPATHLEN];
	char keypath[ABSPATHLEN];

	struct nk_key *key;
	int i, type;
	size_t newsize;
	char *newbuf = NULL;
	char * restrict string = NULL;
	uint64_t val;  /* DWORD/QWORD hex string value */
	struct keyval * restrict kv = NULL;
	struct keyval * restrict newkv = NULL;

	LOAD_WD();

	DLOG("write: %s (%d + %d)\n", path, (int)size, (int)offset);

	if (wd->ro) {
		LOG("write: read-only filesystem\n");
		return -EROFS;
	}

	sanitize_path(path, keypath, node);

	/* Extract type information, remove extension from name */
	type = process_ext(node);
	if (type < 0) {
		LOG("read: invalid type extension: %s\n", path);
		return -EINVAL;
	}

	if (*node == '@') *node = '\0';

	nkofs = get_path_nkofs(wd, keypath, &key, 0);
	if (!nkofs) {
		LOG("read: get_path_nkofs failed: %s\n", keypath);
		return -ENOENT;
	}

	kv = get_val2buf(wd->hive, NULL, nkofs, node, type, TPF_VK_EXACT);
	if (!kv) {
		LOG("write: metadata missing for %s\n", path);
		return -ENOENT;
	}

	newsize = offset + size;
	if(newsize > 8192 || kv->len > 8192) {
		LOG("write: 8 KiB value size limit exceeded: %s\n", path);
		free(kv->data); free(kv);
		return -EFBIG;
	}

	switch(type) {
	case REG_DWORD:
		if (offset != 0 && kv->len > newsize) newsize = kv->len;
		if (offset > kv->len) {
			LOG("write: attempt to write beyond end of file: %s\n", path);
			free(kv->data); free(kv);
			return -EINVAL;
		}
		i = find_nonhex(buf, 9);
		if (i < 1) {
			LOG("write: bad DWORD file format: %s\n", path);
			free(kv->data); free(kv);
			return -EINVAL;
		}
		i = convert_hex(buf, &val, i);
		if (i == -1) {
			LOG("write: bad DWORD file format: %s\n", path);
			free(kv->data); free(kv);
			return -EINVAL;
		}

		kv->len = 4;
		*((uint32_t *)kv->data) = (uint32_t)val;
		i = put_buf2val(wd->hive, kv, nkofs, node, type, TPF_VK_EXACT);

		if (!i) {
			LOG("write: error writing file: %s\n", path);
			free(kv->data); free(kv);
			return -EINVAL;
		}
		break;

	case REG_QWORD:
		if (offset != 0 && kv->len > newsize) newsize = kv->len;
		if (offset > kv->len) {
			LOG("write: attempt to write beyond end of file: %s\n", path);
			free(kv->data); free(kv);
			return -EINVAL;
		}
		i = find_nonhex(buf, 17);
		if (i < 1) {
			LOG("write: bad QWORD file format: %s\n", path);
			free(kv->data); free(kv);
			return -EINVAL;
		}
		i = convert_hex(buf, &val, i);
		if (i == -1) {
			LOG("write: bad QWORD file format: %s\n", path);
			free(kv->data); free(kv);
			return -EINVAL;
		}

		kv->len = 8;
		*((uint64_t *)kv->data) = val;
		i = put_buf2val(wd->hive, kv, nkofs, node, type, TPF_VK_EXACT);

		if (!i) {
			LOG("write: error writing file: %s\n", path);
			free(kv->data); free(kv);
			return -EINVAL;
		}
		break;

	case REG_BINARY:
		if (offset != 0 && kv->len > newsize) newsize = kv->len;
		if (offset > kv->len) {
			LOG("write: attempt to write beyond end of file: %s\n", path);
			free(kv->data); free(kv);
			return -EINVAL;
		}
		newkv = (struct keyval *)malloc(sizeof(struct keyval));
		if (!newkv) {
			LOG("write: failed to allocate memory\n");
			free(kv->data); free(kv);
			return -ENOMEM;
		}

		ALLOC(newkv->data, 1, newsize);
		if (!newkv->data) {
			LOG("write: failed to allocate memory for buffer\n");
			free(newkv); free(kv->data); free(kv);
			return -ENOMEM;
		}

		memcpy(newkv->data, kv->data, kv->len);
		memcpy(((char *)newkv->data + offset), buf, size);
		newkv->len = newsize;
		i = put_buf2val(wd->hive, newkv, nkofs, node, type, TPF_VK_EXACT);
		free(newkv->data); free(newkv); free(kv->data); free(kv);

		if (!i) {
			LOG("write: error writing file: %s\n", path);
			return -EINVAL;
		}
		break;

	case REG_SZ:
	case REG_EXPAND_SZ:
	case REG_MULTI_SZ:
		/* Handling offsets as well as loading existing data makes this complex */
		if (offset != 0 && (kv->len >> 1) > newsize) newsize = kv->len >> 1;
		if (offset > kv->len) {
			LOG("write: attempt to write beyond end of file: %s\n", path);
			free(kv->data); free(kv);
			return -EINVAL;
		}
		newbuf = (char *)malloc(sizeof(char) * (newsize + 1));

		if (!newbuf) {
			LOG("write: failed to allocate memory for buffer\n");
			free(kv->data); free(kv);
			return -ENOMEM;
		}

		/* Copy old message into buffer if offset is specified */
		if (offset != 0) {
			string = string_regw2prog(kv->data, kv->len);
			if (!string) {
				LOG("write: out of memory\n");
				free(newbuf); free(kv->data); free(kv);
				return -ENOMEM;
			}

			for (i = 0; i < (kv->len >> 1); i++) {
				if (string[i] == 0) string[i] = '\n';
				if (type == REG_SZ) break;
			}
			memcpy(newbuf, string, kv->len >> 1);
			free(string);
		}

		newkv = (struct keyval *)malloc(sizeof(struct keyval));
		if (!newkv) {
			LOG("write: out of memory\n");
			free(newbuf); free(kv->data); free(kv);
			return -ENOMEM;
		}

		/* Extra byte for MULTI_SZ null termination */
		ALLOC(newkv->data, 1, (newsize + 1) << 1);

		memcpy((newbuf + offset), buf, size);
		*(newbuf + offset + size) = 0;
		newkv->len = newsize << 1;
		/* Truncate string at first newline */
		if (type != REG_MULTI_SZ) {
			for(i = 0; i < newsize; i++) {
				if (newbuf[i] == '\n' || newbuf[i] == '\r') {
					newkv->len = (i + 1) << 1;
					break;
				}
			}
		} else {
			/* MULTI_SZ is icky. Newlines become nulls! */
			for(i = 0; i < newsize; i++) {
				if (newbuf[i] == '\n' || newbuf[i] == '\r')
					newbuf[i] = '\0';
			}
		}
		cheap_ascii2uni(newbuf, (char *)newkv->data, newsize);
		free(newbuf);
		i = put_buf2val(wd->hive, newkv, nkofs, node, type, TPF_VK_EXACT);
		if(i != newkv->len) {
			LOG("write: short write: %s (%d/%d)\n", path, i, (int)newkv->len);
			free(newkv->data); free(newkv); free(kv->data); free(kv);
			return -ENOSPC;
		}
		free(newkv->data);
		free(newkv);
		free(kv->data);
		free(kv);

		if (!i) {
			LOG("write: error writing file: %s\n", path);
			return -EINVAL;
		}
		break;
	default:
		LOG("write: type %d not supported: %s\n", type, path);
		free(kv->data); free(kv);
		return -EINVAL;
		break;
	}

	if (write_hive(wd->hive)) {
		LOG("write: error writing changes to hive\n");
		return -EPERM;
	}

	return size;
}


/* Create a new empty file (registry value) */
static int winregfs_mknod(const char * const restrict path,
		mode_t mode, dev_t dev)
{
	struct nk_key *key;
	int nkofs, ktype;
	char keypath[ABSPATHLEN];
	char node[ABSPATHLEN];

	LOAD_WD();

	DLOG("mknod: %s\n", path);

	if (wd->ro) {
		LOG("mknod: read-only filesystem\n");
		return -EROFS;
	}

	/* There are quite a few errors to watch out for */
	/* FUSE already handles the "already exists" case */
	if (!(mode & S_IFREG)) {
		LOG("mknod: special files are not allowed\n");
		return -EPERM;
	}

	if (PATH_IS_ROOT(path)) {
		LOG("mknod: no path specified\n");
		return -EEXIST;
	}

	sanitize_path(path, keypath, node);

	ktype = process_ext(node);
	if (ktype < 0) {
		LOG("mknod: bad extension: %s\n", path);
		return -EPERM;
	}

	nkofs = get_path_nkofs(wd, keypath, &key, 0);
	if (!nkofs) {
		LOG("mknod: no offset: %s\n", keypath);
		return -ENOSPC;
	}

	if (!add_value(wd->hive, nkofs, node, ktype)) {
		LOG("mknod: error creating value: %s\n", path);
		return -ENOSPC;
	}
	if (write_hive(wd->hive)) {
		LOG("mknod: error writing changes to hive\n");
		return -EPERM;
	}
#if ENABLE_NKOFS_CACHE
	get_path_nkofs(wd, keypath, &key, 1);
#endif
	return 0;
}


/* Remove a file (registry value) */
static int winregfs_unlink(const char * const restrict path)
{
	struct nk_key *key;
	int nkofs;
	char node[ABSPATHLEN];
	char keypath[ABSPATHLEN];

	LOAD_WD();

	DLOG("unlink: %s\n", path);

	if (wd->ro) {
		LOG("unlink: read-only filesystem\n");
		return -EROFS;
	}

	sanitize_path(path, keypath, node);
	process_ext(node);

	nkofs = get_path_nkofs(wd, keypath, &key, 0);
	if (!nkofs) {
		LOG("unlink: no offset: %s\n", keypath);
		return -ENOENT;
	}

	if (del_value(wd->hive, nkofs, node)) {
		LOG("unlink: cannot delete: %s\n", path);
		return -ENOENT;
	}
	if (write_hive(wd->hive)) {
		LOG("unlink: error writing changes to hive\n");
		return -EPERM;
	}
#if ENABLE_NKOFS_CACHE
	get_path_nkofs(wd, keypath, &key, 1);
#endif
	return 0;
}


/* Make a key (directory); creation mode is ignored */
static int winregfs_mkdir(const char * const restrict path,
		mode_t mode)
{
	struct nk_key *key;
	int nkofs;
	char node[ABSPATHLEN];
	char keypath[ABSPATHLEN];

	LOAD_WD();

	DLOG("mkdir: %s\n", path);

	if (wd->ro) {
		LOG("mkdir: read-only filesystem\n");
		return -EROFS;
	}

	sanitize_path(path, keypath, node);

	nkofs = get_path_nkofs(wd, keypath, &key, 0);
	if (!nkofs) {
		LOG("mkdir: no offset: %s\n", keypath);
		return -ENOENT;
	}

	if (add_key(wd->hive, nkofs, node) == NULL) {
		LOG("mkdir: cannot add key: %s\n", path);
		return -ENOENT;
	}
	if (write_hive(wd->hive)) {
		LOG("mkdir: error writing changes to hive\n");
		return -EPERM;
	}
#if ENABLE_NKOFS_CACHE
	get_path_nkofs(wd, keypath, &key, 1);
#endif
	return 0;
}


/* Remove a key (directory) */
static int winregfs_rmdir(const char * const restrict path)
{
	struct nk_key *key;
	int nkofs;
	char node[ABSPATHLEN];
	char keypath[ABSPATHLEN];

	LOAD_WD();

	DLOG("rmdir: %s\n", path);

	if (wd->ro) {
		LOG("rmdir: read-only filesystem\n");
		return -EROFS;
	}

	sanitize_path(path, keypath, node);

	nkofs = get_path_nkofs(wd, keypath, &key, 0);
	if (!nkofs) {
		LOG("rmdir: no offset: %s\n", keypath);
		return -ENOENT;
	}

	if (del_key(wd->hive, nkofs, node)) {
		LOG("rmdir: cannot delete key: %s\n", path);
		return -ENOENT;
	}
	if (write_hive(wd->hive)) {
		LOG("rmdir: error writing changes to hive\n");
		return -EPERM;
	}
#if ENABLE_NKOFS_CACHE
	get_path_nkofs(wd, keypath, &key, 1);
#endif
	return 0;
}


/* Timestamps not supported, just return success */
static int winregfs_utimens(const char * const restrict path,
		const struct timespec tv[2])
{
	LOAD_WD_LOGONLY();
	LOG("Called but not implemented: utimens\n");
	return 0;
}


/* Truncate is stupid anyway */
static int winregfs_truncate(const char * const restrict path,
		off_t len)
{
	LOAD_WD_LOGONLY();
	LOG("Called but not implemented: truncate (len %d)\n", (int)len);
	return 0;
}

/* FUSE debugging placeholders for when things get "fun" */
/*
static int winregfs_readlink(void)
{ LOAD_WD(); LOG("ERROR: Not implemented: readlink\n"); return -1; }
static int winregfs_symlink(void)
{ LOAD_WD(); LOG("ERROR: Not implemented: symlink\n"); return -1; }
static int winregfs_rename(void)
{ LOAD_WD(); LOG("ERROR: Not implemented: rename\n"); return -1; }
static int winregfs_link(void)
{ LOAD_WD(); LOG("ERROR: Not implemented: link\n"); return -1; }
static int winregfs_chmod(void)
{ LOAD_WD(); LOG("ERROR: Not implemented: chmod\n"); return -1; }
static int winregfs_chown(void)
{ LOAD_WD(); LOG("ERROR: Not implemented: chown\n"); return -1; }
static int winregfs_statfs(void)
{ LOAD_WD(); LOG("ERROR: Not implemented: statfs\n"); return -1; }
static int winregfs_flush(void)
{ LOAD_WD(); LOG("ERROR: Not implemented: flush\n"); return -1; }
static int winregfs_release(void)
{ LOAD_WD(); LOG("ERROR: Not implemented: release\n"); return -1; }
static int winregfs_fsync(void)
{ LOAD_WD(); LOG("ERROR: Not implemented: fsync\n"); return -1; }
static int winregfs_releasedir(void)
{ LOAD_WD(); LOG("ERROR: Not implemented: releasedir\n"); return -1; }
static int winregfs_fsyncdir(void)
{ LOAD_WD(); LOG("ERROR: Not implemented: fsyncdir\n"); return -1; }
static int winregfs_ftruncate(void)
{ LOAD_WD(); LOG("ERROR: Not implemented: ftruncate\n"); return -1; }
static int winregfs_fgetattr(void)
{ LOAD_WD(); LOG("ERROR: Not implemented: fgetattr\n"); return -1; }
*/


/* Required for FUSE to use these functions */
static struct fuse_operations winregfs_oper = {
	.getattr	= winregfs_getattr,
/*	.readlink	= winregfs_readlink, */
	.mknod		= winregfs_mknod,
	.readdir	= winregfs_readdir,
	.mkdir		= winregfs_mkdir,
	.unlink		= winregfs_unlink,
	.rmdir		= winregfs_rmdir,
/*	.symlink	= winregfs_symlink,
	.rename		= winregfs_rename,
	.link		= winregfs_link,
	.chmod		= winregfs_chmod,
	.chown		= winregfs_chown, */
	.truncate	= winregfs_truncate,
	.open		= winregfs_open,
	.read		= winregfs_read,
	.write		= winregfs_write,
	.access		= winregfs_access,
	.utimens	= winregfs_utimens,
/*	.statfs		= winregfs_statfs,
	.flush		= winregfs_flush,
	.release	= winregfs_release,
	.fsync		= winregfs_fsync,
	.releasedir	= winregfs_releasedir,
	.fsyncdir	= winregfs_fsyncdir,
	.ftruncate	= winregfs_ftruncate,
	.fgetattr	= winregfs_fgetattr,
	.lock		= winregfs_lock, */
};


int main(int argc, char *argv[])
{
	struct winregfs_data * restrict wd;
	char file[ABSPATHLEN];
	int i;

	/* Show version and return successfully if requested */
	if (argc == 2 && !strncasecmp(argv[1], "-v", 2)) {
		fprintf(stderr, "Windows Registry Filesystem %s (%s)\n", VER, VERDATE);
		return EXIT_SUCCESS;
	}

	if ((argc < 3) || (argv[argc-2][0] == '-') || (argv[argc-1][0] == '-')) {
		fprintf(stderr, "Windows Registry Filesystem %s (%s)\n", VER, VERDATE);
		fprintf(stderr, "\nUsage: %s [-o ro] [fuse_options] hivename mountpoint\n\n", argv[0]);
		return EXIT_FAILURE;
	}

	/* Pull hive file name from command line and pass to FUSE */
	strncpy(file, argv[argc-2], ABSPATHLEN);
#if ENABLE_THREADED
	argv[argc-2] = argv[argc-1];
	argv[argc-1] = NULL;
	argc--;
#else
	/* Add single-threaded mode switch "-s" to args */
	argv[argc-2] = (char *) malloc(3);
	if (!argv[argc-2]) goto oom;
	strncpy(argv[argc-2], "-s", 3);
#endif

	wd = (struct winregfs_data *) malloc(sizeof(struct winregfs_data));
	if (!wd) goto oom;

	/* Set read-only mode if applicable */
	wd->ro = 0;
	if (argc > 4 && !strncmp(argv[1], "-o", 2)&& !strncmp(argv[2], "ro", 2)) wd->ro = 1;

#if ENABLE_LOGGING
	wd->log = fopen("debug.log", "w");
	if (!wd->log) {
		fprintf(stderr, "Error: couldn't open log file\n");
		return EXIT_FAILURE;
	}
#endif
#if ENABLE_NKOFS_CACHE
	/* malloc() and initialize cache pointers/data */
	wd->last_path[0] = (char *)malloc(sizeof(char) * ABSPATHLEN * CACHE_ITEMS);
	if (!wd->last_path[0]) goto oom;
	for (i=0; i < CACHE_ITEMS; i++) {
		wd->last_path[i] = (wd->last_path[0] + (ABSPATHLEN * i));
		*wd->last_path[i] = '\0';
		wd->hash[i] = 0;
	}
# if ENABLE_THREADED
	wd->lock = (pthread_mutex_t *) malloc(sizeof(pthread_mutex_t));
	if (!wd->lock) goto oom;
	pthread_mutex_init(wd->lock, NULL);
# endif /* THREADED */
	wd->cache_pos = CACHE_ITEMS - 1;
# if ENABLE_NKOFS_CACHE_STATS
	wd->cache_miss = 0;
	wd->cache_hit = 0;
	wd->hash_miss = 0;
	wd->hash_hit = 0;
	wd->hash_fail = 0;
	wd->delay = 1;
# endif
#endif /* NKOFS_CACHE */


	if (!wd->ro) wd->hive = open_hive(file, HMODE_RW);
		else wd->hive = open_hive(file, HMODE_RO);
	if (!wd->hive) {
		fprintf(stderr, "Error: couldn't open %s\n", file);
		return EXIT_FAILURE;
	}
#if ENABLE_LOGGING
	LOG("winregfs %s (%s) started for hive %s\n", VER, VERDATE, file);
#endif
	i = fuse_main(argc, argv, &winregfs_oper, wd);
	close_hive(wd->hive);
#if ENABLE_LOGGING
	LOG("winregfs terminated OK\n");
	fclose(wd->log);
#endif
	free(wd);
	return i;
oom:
	fprintf(stderr, "Error: out of memory\n");
	return EXIT_FAILURE;
}
