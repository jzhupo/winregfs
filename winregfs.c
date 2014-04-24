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
const char *ext[REG_MAX + 1] = {
	"none", "sz", "esz", "bin", "dw", "dwbe", "lnk",
	"msz", "reslist", "fullres", "res_req", "qw", NULL
};

const char slash[] = "_SLASH_";
const int ss = sizeof(slash) - 1;

/*** Non-FUSE helper functions ***/

/* Remove extension and return numeric value for value type */
static int process_ext(char *node)
{
	char *str_ext;
	int i = 0;

	str_ext = strrchr(node, '.');
	/* Check for no-extension case */
	if(str_ext == NULL) return -1;
	*str_ext = '\0';
	str_ext++;
	for (; i < REG_MAX; i++) {
		if(!strncasecmp(str_ext, ext[i], 8)) return i;
	}
	return -1;
}


/* Add the type extension to the registry value name */
static inline void add_val_ext(char *filename, const struct vex_data *vex)
{
	strncpy(filename, vex->name, ABSPATHLEN);
	strncat(filename, ".", ABSPATHLEN);
	strncat(filename, ext[vex->type], ABSPATHLEN);
}


/* Convert slashes to backslashes */
static inline void slash_fix(char *path)
{
	int i;

	for (i = strlen(path); i >= 0; i--) {
		if (path[i] == '/') path[i] = '\\';
	}
}


/* Forward slashes cannot appear in pathname components */
static int escape_fwdslash(char *path)
{
	int pos = 0;
	char *p, *q;
	char temp[ABSPATHLEN];

	LOAD_WD();

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


static int unescape_fwdslash(char *path)
{
	int pos = 0;
	char *p, *q;
	char temp[ABSPATHLEN];

	LOAD_WD();

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
static void log_cache_stats(struct winregfs_data *wd)
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
	LOG("hash: %d miss, %d hit (%3.2f%%), %d fail (%3.2f%%); ",
			wd->hash_miss, wd->hash_hit,
			((wd->hash_hit * 100) / ((h>0) ? h : 1)),
			wd->hash_fail,
			((wd->hash_fail * 100) / ((h>0) ? h : 1)));
}
# endif


static inline void cache_stats(struct winregfs_data *wd, char hit)
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


static inline hash_t cache_hash(const char *string)
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


static int get_path_nkofs(struct winregfs_data *wd, char *keypath, struct nk_key **key)
{
	int nkofs;

#if ENABLE_NKOFS_CACHE
	int i;
	hash_t hash;

	/* Check the cached path to avoid extra traversals */
	hash = cache_hash(keypath);
	LOCK();
	i = wd->cache_pos;
	/* Work backwards in the hash cache ring until we come back
	 * where we started or encounter a zeroed (non-existent) hash */
	while (1) {
		if (!wd->hash[i]) break;  /* 0 = end of recorded hashes */
		if (wd->hash[i] == hash) {
			cache_stats(wd, HASH_HIT);
			if (!strncasecmp(wd->last_path[i], keypath, ABSPATHLEN)) {
				nkofs = wd->last_nkofs[i];
				*key = wd->last_key[i];
				/* DLOG("get_path_nkofs: cache hit: %s %s\n", keypath, wd->last_path[i]); */
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
	/* DLOG("get_path_nkofs: cache miss: %s %s\n", keypath, wd->last_path[i]); */
	cache_stats(wd, CACHE_MISS);
#endif  /* NKOFS_CACHE */

	/* Cached path didn't match, traverse and get offset */
	nkofs = trav_path(wd->hive, 0, keypath, TPF_NK_EXACT);
	if(!nkofs) {
		LOG("get_path_nkofs: trav_path failed: %s\n", keypath);
		return 0;
	}
	nkofs += 4;

	*key = (struct nk_key *)(wd->hive->buffer + nkofs);

#if ENABLE_NKOFS_CACHE
	LOCK();
	if(++wd->cache_pos >= CACHE_ITEMS) wd->cache_pos = 0;
	strncpy(wd->last_path[wd->cache_pos], keypath, ABSPATHLEN);
	wd->last_nkofs[wd->cache_pos] = nkofs;
	wd->last_key[wd->cache_pos] = *key;
	wd->hash[wd->cache_pos] = cache_hash(keypath);
	UNLOCK();
#endif
	return nkofs;
}


/* Converts a path to the required formats for keypath/nodepath usage */
static inline int sanitize_path(const char *path, char *keypath, char *node)
{
	strncpy(keypath, path, ABSPATHLEN);
	strncpy(node, path, ABSPATHLEN);
	dirname(keypath);   /* need to read the root key */
	strncpy(node, basename(node), ABSPATHLEN); 
	slash_fix(keypath);
	unescape_fwdslash(node);
	unescape_fwdslash(keypath);
	return 0;
}
/*** End helper functions ***/


/*** FUSE functions ***/

/* Check if access to a particular file is allowed */
static int winregfs_access(const char *path, int mode)
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
/*	if(mode & W_OK) {
		LOG("access: write requested for read-only filesystem\n");
		errno = EROFS;
		return -1;
	} */

	if (strcmp(path, "/") == 0) return 0;
	sanitize_path(path, keypath, node);

	nkofs = get_path_nkofs(wd, keypath, &key);
	if (!nkofs) {
		LOG("access: no offset: %s\n", keypath);
		errno = ENOENT;
		return -1;
	}

	if (key->no_subkeys) {
		while ((ex_next_n(wd->hive, nkofs, &count, &countri, &ex) > 0)) {
			if (!strncasecmp(node, ex.name, ABSPATHLEN)) {
				DLOG("access: ex_n: %p size %d c %d cri %d\n", path, ex.nk->no_subkeys, count, countri);
				DLOG("access: directory OK: %s\n", node);
				FREE(ex.name);
				return 0;
			} else FREE(ex.name);
		}
	}

	count = 0;
	if (key->no_values) {
		while ((ex_next_v(wd->hive, nkofs, &count, &vex) > 0)) {
			if (strlen(vex.name) == 0) strncpy(filename, "@.sz", 5);
			else add_val_ext(filename, &vex);
			FREE(vex.name);
			if (!strncasecmp(node, filename, ABSPATHLEN)) {
				if(!(mode & X_OK)) {
					DLOG("access: OK: ex_v: %p size %d c %d\n", path, vex.size, count);
					return 0;
				} else {
					DLOG("access: exec not allowed: ex_v: %p size %d c %d\n", path, vex.size, count);
					errno = EACCES;
					return -1;
				}
			}
		}
	}
	LOG("access: not found: %s\n", path);
	errno = ENOENT;
	return -1;
}


static int winregfs_getattr(const char *path, struct stat *stbuf)
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

	DLOG("getattr: %s\n", path);

	if (strcmp(path, "/") == 0) {
		stbuf->st_mode = S_IFDIR | 0555;
		stbuf->st_nlink = 2;
		stbuf->st_size = 1;
		return 0;
	}
	sanitize_path(path, keypath, node);

	memset(stbuf, 0, sizeof(struct stat));

	nkofs = get_path_nkofs(wd, keypath, &key);
	if (!nkofs) {
		LOG("getattr: no offset: %s\n", keypath);
		return -ENOENT;
	}

	if (key->no_subkeys) {
		while ((ex_next_n(wd->hive, nkofs, &count, &countri, &ex) > 0)) {
			if (!strncasecmp(node, ex.name, ABSPATHLEN)) {
				stbuf->st_mode = S_IFDIR | 0777;
				stbuf->st_nlink = 2;
				stbuf->st_size = ex.nk->no_subkeys;
				DLOG("getattr: ex_n: %p size %d c %d cri %d\n", path, ex.nk->no_subkeys, count, countri);
				FREE(ex.name);
				return 0;
			} else FREE(ex.name);
		}
	}

	count = 0;
	if (key->no_values) {
		while ((ex_next_v(wd->hive, nkofs, &count, &vex) > 0)) {
			if (strlen(vex.name) == 0) strncpy(filename, "@.sz", 5);
			else add_val_ext(filename, &vex);
			if (!strncasecmp(node, filename, ABSPATHLEN)) {
				stbuf->st_mode = S_IFREG | 0666;
				stbuf->st_nlink = 1;
				stbuf->st_size = vex.size;
				DLOG("getattr: ex_v: %p size %d c %d\n", path, vex.size, count);
				return 0;
			} else FREE(vex.name);
		}
	}
	LOG("getattr: not found: %s\n", path);
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
	char keypath[ABSPATHLEN];

	LOAD_WD();

	DLOG("readdir: %s\n", path);

	strncpy(keypath, path, ABSPATHLEN);
	slash_fix(keypath);
	unescape_fwdslash(keypath);

	nkofs = get_path_nkofs(wd, keypath, &key);
	if (!nkofs) {
		LOG("readdir: get_path_nkofs failed: %s\n", keypath);
		return -ENOENT;
	}

	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);

	if (key->no_subkeys) {
		while ((ex_next_n(wd->hive, nkofs, &count, &countri, &ex) > 0)) {
			DLOG("readdir: n_filler: %s\n", ex.name);
			strncpy(filename, ex.name, ABSPATHLEN);
			FREE(ex.name);
			escape_fwdslash(filename);
			filler(buf, filename, NULL, 0);
		}
	}

	count = 0;
	if (key->no_values) {
		while ((ex_next_v(wd->hive, nkofs, &count, &vex) > 0)) {
			if (strlen(vex.name) == 0) strncpy(filename, "@.sz", 5);
			else add_val_ext(filename, &vex);
			FREE(vex.name);
			escape_fwdslash(filename);
			DLOG("readdir: v_filler: %s\n", filename);
			filler(buf, filename, NULL, 0);
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
	char keypath[ABSPATHLEN];
	char node[ABSPATHLEN];

	LOAD_WD();

	/* Read-only support (possible future feature) */
/*	if ((fi->flags & 3) != O_RDONLY) {
		LOG("open: Read-only: %s\n", path);
		return -EACCES;
	} */

	if (strcmp(path, "/") == 0) {
		LOG("open: Is a directory: %s\n", path);
		return -EISDIR;
	}
	sanitize_path(path, keypath, node);

	nkofs = get_path_nkofs(wd, keypath, &key);
	if (!nkofs) {
		LOG("open: get_path_nkofs failed: %s\n", keypath);
		return -ENOENT;
	}

	if (key->no_subkeys) {
		while ((ex_next_n(wd->hive, nkofs, &count, &countri, &ex) > 0)) {
			if (!strncasecmp(node, ex.name, ABSPATHLEN)) {  /* remove leading slash */
				LOG("open: Is a directory: %s\n", node);
				FREE(ex.name);
				return -EISDIR;
			} else FREE(ex.name);
		}
	}

	count = 0;
	if (key->no_values) {
		while ((ex_next_v(wd->hive, nkofs, &count, &vex) > 0)) {
			if (strlen(vex.name) == 0) strncpy(filename, "@.sz", 5);
			else add_val_ext(filename, &vex);
			FREE(vex.name);
			if (!strncasecmp(node, filename, ABSPATHLEN)) return 0;
		}
	}
	LOG("open: No such file or directory for %s\n", path);
	return -ENOENT;
}

static int winregfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
	int nkofs;
	char node[ABSPATHLEN];
	char keypath[ABSPATHLEN];

	struct nk_key *key;
	void *data;
	size_t len;
	int i, type, ktype = -1;
	int used_string = 0;  /* 1 if string should be freed */
	char *string = NULL;
	struct keyval *kv = NULL;

	LOAD_WD();

	sanitize_path(path, keypath, node);

	/* Extract type information, remove extension from name */
	ktype = process_ext(node);
	if (ktype < 0) {
		LOG("read: invalid type extension: %s\n", path);
		return -EINVAL;
	}

	if (*node == '@') *node = '\0';

	nkofs = get_path_nkofs(wd, keypath, &key);
	if (!nkofs) {
		LOG("read: get_path_nkofs failed: %s\n", keypath);
		return -ENOENT;
	}

	type = get_val_type(wd->hive, nkofs, node, TPF_VK_EXACT);
	if (type == -1) {
		LOG("read: No such value %s\n", node);
		return -EINVAL;
	}

	len = get_val_len(wd->hive, nkofs, node, TPF_VK_EXACT);
	if (len < 0) {
		LOG("read: Value %s is not readable\n", node);
		return -EINVAL;
	}

	kv = get_val2buf(wd->hive, NULL, nkofs, node, 0, TPF_VK_EXACT);

	if (!kv) {
		LOG("read: Value %s could not fetch data\n", node);
		return -EINVAL;
	}
	data = (void *)&(kv->data);

	switch (type) {
	case REG_SZ:
	case REG_EXPAND_SZ:
	case REG_MULTI_SZ:
		if(!len) break;
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


/* Create a new empty file */
static int winregfs_mknod(const char *path, mode_t mode, dev_t dev)
{
	struct nk_key *key;
	int nkofs, ktype;
	char keypath[ABSPATHLEN];
	char node[ABSPATHLEN];

	LOAD_WD();

	DLOG("mknod: %s\n", path);

	/* There are quite a few errors to watch out for */
	/* FUSE already handles the "already exists" case */
	if(!(mode & S_IFREG)) {
		LOG("mknod: special files are not allowed\n");
		errno = EPERM;
		return -1;
	}

	if (strcmp(path, "/") == 0) {
		LOG("mknod: no path specified\n");
		errno = EEXIST;
		return -1;
	}

	sanitize_path(path, keypath, node);

	ktype = process_ext(node);
	if(ktype < 0) {
		LOG("mknod: bad extension: %s\n", path);
		errno = EPERM;
		return -1;
	}

	nkofs = get_path_nkofs(wd, keypath, &key);
	if (!nkofs) {
		LOG("mknod: no offset: %s\n", keypath);
		errno = ENOSPC;
		return -1;
	}

	if(!add_value(wd->hive, nkofs, node, ktype)) {
		LOG("mknod: error creating value: %s\n", path);
		errno = ENOSPC;
		return -1;
	}
	if(writeHive(wd->hive)) {
		LOG("mknod: error writing changes to hive\n");
		errno = EPERM;
		return -1;
	}
	return 0;
}


static int winregfs_unlink(const char *path)
{
	struct nk_key *key;
	int nkofs;
	char node[ABSPATHLEN];
	char keypath[ABSPATHLEN];

	LOAD_WD();

	DLOG("unlink: %s\n", path);

        sanitize_path(path, keypath, node);
	process_ext(node);

        nkofs = get_path_nkofs(wd, keypath, &key);
        if (!nkofs) {
                LOG("unlink: no offset: %s\n", keypath);
                errno = ENOENT;
                return -1;
        }

	if(del_value(wd->hive, nkofs, node)) {
                LOG("unlink: cannot delete: %s\n", path);
                errno = ENOENT;
                return -1;
	}
	if(writeHive(wd->hive)) {
		LOG("unlink: error writing changes to hive\n");
		errno = EPERM;
		return -1;
	}
	return 0;
}


/* Make a key (directory); creation mode is ignored */
static int winregfs_mkdir(const char *path, mode_t mode)
{
	struct nk_key *key;
	int nkofs;
	char node[ABSPATHLEN];
	char keypath[ABSPATHLEN];

	LOAD_WD();

	DLOG("mkdir: %s\n", path);

        sanitize_path(path, keypath, node);

        nkofs = get_path_nkofs(wd, keypath, &key);
        if (!nkofs) {
                LOG("mkdir: no offset: %s\n", keypath);
                errno = ENOENT;
                return -1;
        }

	if(add_key(wd->hive, nkofs, node) == NULL) {
                LOG("mkdir: cannot add key: %s\n", path);
                errno = ENOENT;
                return -1;
	}
	if(writeHive(wd->hive)) {
		LOG("mkdir: error writing changes to hive\n");
		errno = EPERM;
		return -1;
	}
	return 0;
}


/* Remove a key (directory) */
static int winregfs_rmdir(const char *path)
{
	struct nk_key *key;
	int nkofs;
	char node[ABSPATHLEN];
	char keypath[ABSPATHLEN];

	LOAD_WD();

	DLOG("rmdir: %s\n", path);

        sanitize_path(path, keypath, node);

        nkofs = get_path_nkofs(wd, keypath, &key);
        if (!nkofs) {
                LOG("rmdir: no offset: %s\n", keypath);
                errno = ENOENT;
                return -1;
        }

	if(del_key(wd->hive, nkofs, node)) {
                LOG("rmdir: cannot delete key: %s\n", path);
                errno = ENOENT;
                return -1;
	}
	if(writeHive(wd->hive)) {
		LOG("rmdir: error writing changes to hive\n");
		errno = EPERM;
		return -1;
	}
	return 0;
}


/* Timestamps not supported, just return success */
static int winregfs_utimens(const char *path, const struct timespec tv[2])
{
	return 0;
}


/* Required for FUSE to use these functions */
static struct fuse_operations winregfs_oper = {
	.getattr	= winregfs_getattr,
	.mknod		= winregfs_mknod,
	.readdir	= winregfs_readdir,
	.mkdir		= winregfs_mkdir,
	.rmdir		= winregfs_rmdir,
	.open		= winregfs_open,
	.read		= winregfs_read,
	.access		= winregfs_access,
	.unlink		= winregfs_unlink,
	.utimens	= winregfs_utimens,
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

#if ENABLE_LOGGING
	wd->log = fopen("debug.log", "w");
	if (!wd->log) {
		fprintf(stderr, "Error: couldn't open log file\n");
		return 1;
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
	if (!wd->lock) {
		goto oom;
	}
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
	wd->hive = openHive(file, HMODE_RW);
	if (!wd->hive) {
		fprintf(stderr, "Error: couldn't open %s\n", file);
		return 1;
	}
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
