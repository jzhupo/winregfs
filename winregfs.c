/*
 * Windows Registry FUSE Filesystem
 *
 * Mounts a Windows registry hive file as a filesystem using FUSE
 * Registry keys become directories and values become files
 * Value files have an extension based on the value type
 * (blah.sz = REG_SZ string; blah.dw = REG_DWORD 32-bit number)
 *
 * Written by Jody Bruchon <jody@jodybruchon.com> 2014-04-20
 *
 * Licensed under GNU GPL v2. See LICENSE and README for details.
 *
 * TODO:
 *
 * * Change REG_DWORD etc. to hex text instead of raw binary data
 *
 * * Add write support
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libgen.h>
#include <pthread.h>
#include "ntreg.h"
#include "winregfs.h"

/* Value type file extensions */
const char *ext[REG_MAX+1] = {
	"none", "sz", "esz", "bin", "dw", "dwbe", "lnk",
	"msz", "reslist", "fullres", "res_req", "qw",
};

/* Path parsing requires backslashes */
inline void slash_fix(char *path)
{
	int i;

	for (i = strlen(path); i >= 0; i--) {
		if (path[i] == '/') path[i] = '\\';
	}
}

#if ENABLE_NKOFS_CACHE_STATS
# if ENABLE_LOGGING
void log_cache_stats(struct winregfs_data *wd)
{
	float c, h;
	time_t ctime;

	/* c, h are checked to prevent divide by zero errors */
	if (wd->delay--) return;
	wd->delay = 100;
	c = wd->cache_miss + wd->cache_hit;
	h = wd->hash_miss + wd->hash_hit;
	LOG("cache: %d miss, %d hit (%3.2f%%); ",
			wd->cache_miss, wd->cache_hit,
			((wd->cache_hit * 100) / ((c>0) ? c : 1)));
	LOG("hash: %d miss, %d hit (%3.2f%%), %d fail (%3.2f%%); ",
			wd->hash_miss, wd->hash_hit,
			((wd->hash_hit * 100) / ((h>0) ? h : 1)),
			wd->hash_fail,
			((wd->hash_fail * 100) / ((h>0) ? h : 1)));
	LOG("running %ds\n", time(NULL) - (wd->start_time));
}
# endif

inline void cache_stats(struct winregfs_data *wd, char hit)
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

inline hash_t cache_hash(const char *string)
{
	hash_t hash = 0x11;
	hash_t *input;
	char *tail;
	int count, l, s;

	input = (hash_t *)string;
	l = strlen(string);
	s = l / sizeof(hash_t);
	count = s;
	for (; count > 0; count--) {
		hash ^= (*input);
		input++;
	}
	/* Handle the character tail that isn't in the hash yet */
	tail = (char *)input - ((sizeof(hash_t) - (l - s * sizeof(hash_t))));
	hash ^= (hash_t) *tail;
	if (!hash) return ~hash;  /* Never return 0 */
	else return hash;
}

int get_path_nkofs(struct winregfs_data *wd, char *hivepath, struct nk_key **key)
{
	int nkofs;

#if ENABLE_NKOFS_CACHE
	int i;
	hash_t hash;

	/* Check the cached path to avoid extra traversals */
	hash = cache_hash(hivepath);
	LOCK();
	i = wd->cache_pos;
	/* Work backwards in the hash cache ring until we come back
	 * where we started or encounter a zeroed (non-existent) hash */
	while (1) {
		if (!wd->hash[i]) break;  /* 0 = end of recorded hashes */
		if (wd->hash[i] == hash) {
			cache_stats(wd, HASH_HIT);
			if (!strncasecmp(wd->last_path[i], hivepath, ABSPATHLEN)) {
				nkofs = wd->last_nkofs[i];
				*key = wd->last_key[i];
				DLOG("get_path_nkofs: cache hit: %s %s\n", hivepath, wd->last_path[i]);
				cache_stats(wd, CACHE_HIT);
				UNLOCK();
				return nkofs;
			} else cache_stats(wd, HASH_FAIL);
		} else cache_stats(wd, HASH_MISS);
		if (!i) i = CACHE_ITEMS;
		i--;
		if (i == wd->cache_pos) break;
	}
	UNLOCK();
	DLOG("get_path_nkofs: cache miss: %s %s\n", hivepath, wd->last_path[i]);
	cache_stats(wd, CACHE_MISS);
#endif  /* NKOFS_CACHE */

	/* Cached path didn't match, traverse and get offset */
	nkofs = trav_path(wd->hive, 0, hivepath, TPF_NK_EXACT);
	if(!nkofs) {
		LOG("get_path_nkofs: trav_path failed: %s\n", hivepath);
		return 0;
	}
	nkofs += 4;

	*key = (struct nk_key *)(wd->hive->buffer + nkofs);

#if ENABLE_NKOFS_CACHE
	LOCK();
	if(++wd->cache_pos >= CACHE_ITEMS) wd->cache_pos = 0;
	strncpy(wd->last_path[wd->cache_pos], hivepath, ABSPATHLEN);
	wd->last_nkofs[wd->cache_pos] = nkofs;
	wd->last_key[wd->cache_pos] = *key;
	wd->hash[wd->cache_pos] = cache_hash(hivepath);
	UNLOCK();
#endif
	return nkofs;
}

static int winregfs_getattr(const char *path, struct stat *stbuf)
{
	struct nk_key *key;
	int nkofs;
	struct ex_data ex;
	struct vex_data vex;
	int count = 0, countri = 0;
	char filename[ABSPATHLEN];
	char hivepath[ABSPATHLEN];
	char nodepath[ABSPATHLEN];

	struct winregfs_data *wd;
	wd = fuse_get_context()->private_data;

	DLOG("getattr: %s\n", path);
	strncpy(hivepath, path, ABSPATHLEN);  /* because const char *path */
	strncpy(nodepath, path, ABSPATHLEN);
	dirname(hivepath);   /* need to read the root key */
	strncpy(nodepath, basename(nodepath), ABSPATHLEN);   /* need to read the root key */
	slash_fix(hivepath);

	memset(stbuf, 0, sizeof(struct stat));

	if (strcmp(path, "/") == 0) {
		stbuf->st_mode = S_IFDIR | 0555;
		stbuf->st_nlink = 2;
		stbuf->st_size = 1;
		return 0;
	}

	nkofs = get_path_nkofs(wd, hivepath, &key);
	if (!nkofs) {
		LOG("getattr: no offset: %s\n", hivepath);
		return -ENOENT;
	}

	if (key->no_subkeys) {
		while ((ex_next_n(wd->hive, nkofs, &count, &countri, &ex) > 0)) {
			if (!strncasecmp(nodepath, ex.name, ABSPATHLEN)) {  /* remove leading slash */
				stbuf->st_mode = S_IFDIR | 0555;
				stbuf->st_nlink = 2;
				stbuf->st_size = ex.nk->no_subkeys;
				return 0;
			}
			FREE(ex.name);
		}
	}

	count = 0;
	if (key->no_values) {
		while ((ex_next_v(wd->hive, nkofs, &count, &vex) > 0)) {
			if (strlen(vex.name) == 0) strncpy(filename, "@", 2);
			else strncpy(filename, vex.name, ABSPATHLEN);
			strncat(filename, ".", ABSPATHLEN);
			strncat(filename, ext[vex.type], ABSPATHLEN);
			if (!strncasecmp(nodepath, filename, ABSPATHLEN)) {
				stbuf->st_mode = S_IFREG | 0444;
				stbuf->st_nlink = 1;
				stbuf->st_size = vex.size;
				return 0;
			}
			FREE(vex.name);
		}
	}
	return -ENOENT;
}

static int winregfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi)
{
	struct nk_key *key;
	int nkofs;
	struct ex_data ex;
	struct vex_data vex;
	int count = 0, countri = 0;
	char filename[ABSPATHLEN];
	char hivepath[ABSPATHLEN];

	struct winregfs_data *wd;
	wd = fuse_get_context()->private_data;

	DLOG("readdir: %s\n", path);
	strncpy(hivepath, path, ABSPATHLEN);  /* because const char *path */
	slash_fix(hivepath);

	nkofs = get_path_nkofs(wd, hivepath, &key);
	if (!nkofs) {
		LOG("readdir: get_path_nkofs failed: %s\n", hivepath);
		return -ENOENT;
	}

	if (key->no_subkeys) {
		while ((ex_next_n(wd->hive, nkofs, &count, &countri, &ex) > 0)) {
			filler(buf, ex.name, NULL, 0);
			FREE(ex.name);
		}
	}

	count = 0;
	if (key->no_values) {
		while ((ex_next_v(wd->hive, nkofs, &count, &vex) > 0)) {
			if (strlen(vex.name) == 0) strncpy(filename, "@", 2);
			else strncpy(filename, vex.name, ABSPATHLEN);
			strncat(filename, ".", ABSPATHLEN);
			strncat(filename, ext[vex.type], ABSPATHLEN);
			filler(buf, filename, NULL, 0);
			FREE(vex.name);
		}
	}
	return 0;
}

static int winregfs_open(const char *path, struct fuse_file_info *fi)
{
	struct nk_key *key;
	int nkofs;
	struct ex_data ex;
	struct vex_data vex;
	int count = 0, countri = 0;
	char filename[ABSPATHLEN];
	char hivepath[ABSPATHLEN];
	char nodepath[ABSPATHLEN];

	struct winregfs_data *wd;
	wd = fuse_get_context()->private_data;

	/* FIXME: Force read-only access until write support added */
	if ((fi->flags & 3) != O_RDONLY) {
		LOG("open: Read-only: %s\n", path);
		return -EACCES;
	}
	/* XXX: End force read-only support */

	strncpy(hivepath, path, ABSPATHLEN);
	strncpy(nodepath, path, ABSPATHLEN);
	dirname(hivepath);   /* need to read the root key */
	strncpy(nodepath, basename(nodepath), ABSPATHLEN);   /* need to read the root key */
	slash_fix(hivepath);

	if (strcmp(path, "/") == 0) {
		LOG("open: Is a directory: %s\n", path);
		return -EISDIR;
	}

	nkofs = get_path_nkofs(wd, hivepath, &key);
	if (!nkofs) {
		LOG("open: get_path_nkofs failed: %s\n", hivepath);
		return -ENOENT;
	}

	if (key->no_subkeys) {
		while ((ex_next_n(wd->hive, nkofs, &count, &countri, &ex) > 0)) {
			if (!strncasecmp(nodepath, ex.name, ABSPATHLEN)) {  /* remove leading slash */
				LOG("open: Is a directory: %s\n", nodepath);
				return -EISDIR;
			}
			FREE(ex.name);
		}
	}

	count = 0;
	if (key->no_values) {
		while ((ex_next_v(wd->hive, nkofs, &count, &vex) > 0)) {
			if (strlen(vex.name) == 0) strncpy(filename, "@", 2);
			else strncpy(filename, vex.name, ABSPATHLEN);
			strncat(filename, ".", ABSPATHLEN);
			strncat(filename, ext[vex.type], ABSPATHLEN);
			if (!strncasecmp(nodepath, filename, ABSPATHLEN)) return 0;
			FREE(vex.name);
		}
	}
	LOG("open: No such file or directory for %s\n", path);
	return -ENOENT;
}

static int winregfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
	int nkofs;
	char nodepath[ABSPATHLEN];
	char hivepath[ABSPATHLEN];

	struct nk_key *key;
	void *data;
	size_t len;
	int i, type, ktype = -1;
	int used_string = 0;  /* 1 if string should be freed */
	char *str_ext, *string = NULL;
	struct keyval *kv = NULL;

	struct winregfs_data *wd;
	wd = fuse_get_context()->private_data;

	strncpy(hivepath, path, ABSPATHLEN);
	strncpy(nodepath, path, ABSPATHLEN);
	dirname(hivepath);   /* need to read the root key */
	strncpy(nodepath, basename(nodepath), ABSPATHLEN);   /* need to read the root key */
	slash_fix(hivepath);

	/* Extract type information, remove extension from name */
	str_ext = strrchr(nodepath, '.');
	*str_ext = '\0';
	str_ext++;
	for (i = 0; i < REG_MAX; i++) {
		if(!strncasecmp(str_ext, ext[i], 8)) ktype = i;
	}
	if (ktype < 0) {
		LOG("read: invalid type extension %s\n", str_ext);
		return -EINVAL;
	}

	if (*nodepath == '@') *nodepath = '\0';

	nkofs = get_path_nkofs(wd, hivepath, &key);
	if (!nkofs) {
		LOG("read: get_path_nkofs failed: %s\n", hivepath);
		return -ENOENT;
	}

	type = get_val_type(wd->hive, nkofs, nodepath, TPF_VK_EXACT);
	if (type == -1) {
		LOG("read: No such value %s\n",nodepath);
		return -EINVAL;
	}

	len = get_val_len(wd->hive, nkofs, nodepath, TPF_VK_EXACT);
	if (!len) {
		LOG("read: Value %s has zero length\n",nodepath);
		return -EINVAL;
	}

	kv = get_val2buf(wd->hive, NULL, nkofs, nodepath, 0, TPF_VK_EXACT);

	if (!kv) {
		LOG("read: Value %s could not fetch data\n",nodepath);
		return -EINVAL;
	}
	data = (void *)&(kv->data);

	switch (type) {
	case REG_SZ:
	case REG_EXPAND_SZ:
	case REG_MULTI_SZ:
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
	case REG_DWORD:
		len = 4;
		string = data;
		break;
	case REG_BINARY:
		string = data;
		break;
	default:
		LOG("read: Cannot handle type %d\n", type);
		return -EINVAL;
	}

	if (offset < len) {
		if (offset + size > len) size = len - offset;
		memcpy(buf, string + offset, size);
	} else size = 0;

	if (used_string) FREE(string);
	FREE(kv);
	return size;
}

/* Required for FUSE to use these functions */
static struct fuse_operations winregfs_oper = {
	.getattr	= winregfs_getattr,
	.readdir	= winregfs_readdir,
	.open		= winregfs_open,
	.read		= winregfs_read,
};


int main(int argc, char *argv[])
{
	struct winregfs_data *wd;
	char file[ABSPATHLEN];
	int i;

	if ((argc < 3) || (argv[argc-2][0] == '-') || (argv[argc-1][0] == '-')) {
		fprintf(stderr, "Windows Registry Filesystem %s (%s)\n", VER, VERDATE);
		fprintf(stderr, "\nUsage: %s hivename mountpoint\n\n", argv[0]);
		return 1;
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
	wd->hive = openHive(file, HMODE_RW);
	if (!wd->hive) {
		fprintf(stderr, "Error: couldn't open %s\n", file);
		return 1;
	}
#if ENABLE_LOGGING
	wd->log = fopen("debug.log", "w");
	if (!wd->log) {
		fprintf(stderr, "Error: couldn't open log file\n");
		return 1;
	}
#endif
#if ENABLE_NKOFS_CACHE
	for (i=0; i < CACHE_ITEMS; i++) {
		wd->last_path[i] = (char *)malloc(sizeof(char) * ABSPATHLEN);
		if (!wd->last_path[i]) goto oom;
		*wd->last_path[i] = '\0';
		wd->hash[i] = 0;
	}
# if ENABLE_THREADED
	wd->lock = (pthread_mutex_t *) malloc(sizeof(pthread_mutex_t));
	if (!wd->lock) {
		goto oom;
	}
	pthread_mutex_init(wd->lock, NULL);
# endif /* THREADED */
	wd->cache_pos = CACHE_ITEMS - 1;
#if ENABLE_NKOFS_CACHE_STATS
	wd->cache_miss = 0;
	wd->cache_hit = 0;
	wd->hash_miss = 0;
	wd->hash_hit = 0;
	wd->hash_fail = 0;
	wd->delay = 1;
	wd->start_time = time(NULL);
# endif
#endif /* NKOFS_CACHE */
	i = fuse_main(argc, argv, &winregfs_oper, wd);
	closeHive(wd->hive);
	LOG("winregfs terminated OK\n");
#if ENABLE_LOGGING
	fclose(wd->log);
#endif
	free(wd);
	return i;
oom:
	fprintf(stderr, "Error: out of memory\n");
	return 1;
}
