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
 * * Finish write support
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

/* Return offset to the first non-hexadecimal char in string */
static int find_nonhex(const char *string, int len)
{
	unsigned char q;
	int offset;

	if(*string == 0) return -1;
	for(offset = 0; offset < len; offset++) {
		if(*(string + offset) == 0) return offset;
		q = *(string + offset) - 48;  /* ASCII 0-9 to real 0-9 */
		if(q > 48) q -= 39;
		if(q < 0 || q > 15) return offset;
	}
	return -1;
}


/* Convert hex string to integer */
static int convert_hex(const char *string, uint64_t *dest, int len)
{
	unsigned char q;
	int offset;

	*dest = 0;

	if(*string == 0) return -1;
	for(offset = 0; offset < len; offset++) {
		if(*(string + offset) == 0) return 0;
		*dest <<= 4;  /* Shift for each character processed */
		q = *(string + offset) - 48;  /* ASCII 0-9 to real 0-9 */
		if(q > 48) q -= 39;
		if(q < 0 || q > 15) return -1;
		*dest += q;
	}
	return 0;
}


/* Convert value to hex string, return string length */
static int bytes2hex(char *string, const void *data, const int bytes)
{
	int i, j = 0;
	unsigned char c;

	for(i = bytes - 1; i >= 0; i--) {
		c = *((char *)data + i);
		string[j] = (c >> 4) + 48;
		if(string[j] > 57) string[j] += 39;
		j++;
		string[j] = (c & 15) + 48;
		if(string[j] > 57) string[j] += 39;
		j++;
	}
	string[j] = '\n'; j++;
	string[j] = '\0';
	return (bytes << 1) + 2;
}

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


/* Reverse escape_fwdslash */
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


/* Caching offset fetcher. If update_cache is nonzero, the
 * function call will refresh the cache entry for the path
 * and stop (useful for things that modify directories)
 */
static int get_path_nkofs(struct winregfs_data *wd, char *keypath,
		struct nk_key **key, int update_cache)
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
				if(!update_cache) {
					nkofs = wd->last_nkofs[i];
					*key = wd->last_key[i];
					cache_stats(wd, CACHE_HIT);
					UNLOCK();
					return nkofs;
				} else {
					nkofs = trav_path(wd->hive, 0, keypath, TPF_NK_EXACT);
					if(!nkofs) {
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
		if(update_cache) return 0;
		if (!i) i = CACHE_ITEMS;
		i--;
		if (i == wd->cache_pos) break;
	}

	UNLOCK();

	cache_stats(wd, CACHE_MISS);
#endif  /* NKOFS_CACHE */

	/* Cached path didn't match (or cache disabled), traverse and get offset */
	nkofs = trav_path(wd->hive, 0, keypath, TPF_NK_EXACT);
	if(!nkofs) {
		LOG("get_path_nkofs: trav_path failed: %s\n", keypath);
		return 0;
	}
	nkofs += 4;

	*key = (struct nk_key *)(wd->hive->buffer + nkofs);

#if ENABLE_NKOFS_CACHE
	/* Increment cache ring position, place new cache item */
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

	nkofs = get_path_nkofs(wd, keypath, &key, 0);
	if (!nkofs) {
		LOG("access: no offset: %s\n", keypath);
		errno = ENOENT;
		return -1;
	}

	if (key->no_subkeys) {
		while ((ex_next_n(wd->hive, nkofs, &count, &countri, &ex) > 0)) {
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
		while ((ex_next_v(wd->hive, nkofs, &count, &vex) > 0)) {
			if (strlen(vex.name) == 0) strncpy(filename, "@.sz", 5);
			else add_val_ext(filename, &vex);
			free(vex.name);
			if (!strncasecmp(node, filename, ABSPATHLEN)) {
				if(!(mode & X_OK)) {
					DLOG("access: OK: ex_v: %p size %d c %d\n",
							path, vex.size, count);
					return 0;
				} else {
					DLOG("access: exec not allowed: ex_v: %p size %d c %d\n",
							path, vex.size, count);
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
	char check1[ABSPATHLEN];
	char check2[ABSPATHLEN];
	char *token;

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

	nkofs = get_path_nkofs(wd, keypath, &key, 0);
	if (!nkofs) {
		LOG("getattr: no offset: %s\n", keypath);
		return -ENOENT;
	}

	DLOG("getattr: retrieved key: %p\n", (void *)key);

	if (key->no_subkeys) {
		while ((ex_next_n(wd->hive, nkofs, &count, &countri, &ex) > 0)) {
			if (!strncasecmp(node, ex.name, ABSPATHLEN)) {
				stbuf->st_mode = S_IFDIR | 0777;
				stbuf->st_nlink = 2;
				stbuf->st_size = ex.nk->no_subkeys;
				DLOG("getattr: ex_n: %p size %d c %d cri %d\n",
						path, ex.nk->no_subkeys, count, countri);
				free(ex.name);
				return 0;
			} else free(ex.name);
		}
	}

	count = 0;
	if (key->no_values) {
		while ((ex_next_v(wd->hive, nkofs, &count, &vex) > 0)) {
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
				stbuf->st_mode = S_IFREG | 0666;
				stbuf->st_nlink = 1;
				switch(vex.type) {
				case REG_QWORD:
					stbuf->st_size = 17;
					break;
				case REG_DWORD:
					stbuf->st_size = 9;
					break;
				default:
					stbuf->st_size = vex.size;
				}
				DLOG("getattr: ex_v: %p size %d c %d\n",
						path, vex.size, count);
				return 0;
			}

			/* Prevent creation of conflicting files */
			strncpy(check1, node, ABSPATHLEN);
			token = strrchr(check1, '.');
			if(!token) DLOG("TOKEN 1 BAD  %s  %s\n", node, check1);
			*token = '\0';
			strncpy(check2, filename, ABSPATHLEN);
			if(!token) DLOG("TOKEN 2 BAD\n");
			token = strrchr(check2, '.');
			*token = '\0';
			if(!strncasecmp(check1, check2, ABSPATHLEN)) {
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

	if (key->no_subkeys) {
		while ((ex_next_n(wd->hive, nkofs, &count, &countri, &ex) > 0)) {
			DLOG("readdir: n_filler: %s\n", ex.name);
			strncpy(filename, ex.name, ABSPATHLEN);
			free(ex.name);
			escape_fwdslash(filename);
			filler(buf, filename, NULL, 0);
		}
	}

	count = 0;
	if (key->no_values) {
		while ((ex_next_v(wd->hive, nkofs, &count, &vex) > 0)) {
			if (strlen(vex.name) == 0) strncpy(filename, "@.sz", 5);
			else add_val_ext(filename, &vex);
			free(vex.name);
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

	if (strcmp(path, "/") == 0) {
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
		while ((ex_next_n(wd->hive, nkofs, &count, &countri, &ex) > 0)) {
			if (!strncasecmp(node, ex.name, ABSPATHLEN)) {  /* remove leading slash */
				LOG("open: Is a directory: %s\n", node);
				free(ex.name);
				return -EISDIR;
			} else free(ex.name);
		}
	}

	count = 0;
	if (key->no_values) {
		while ((ex_next_v(wd->hive, nkofs, &count, &vex) > 0)) {
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

static int winregfs_read(const char *path, char *buf, size_t size,
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
			while ((ex_next_v(wd->hive, nkofs, &count, &vex) > 0)) {
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
	if (*node == '@') *node = '\0';

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
	data = (void *)(kv->data);

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
	case REG_QWORD:
		len = bytes2hex(dqw, data, 8);
		string = dqw;
		break;
	case REG_DWORD:
		len = bytes2hex(dqw, data, 4);
		string = dqw;
		break;
	case REG_BINARY:
		string = data;
		break;
	default:
		LOG("read: Cannot handle type %d\n", type);
		free(kv->data); free(kv);
		return -EINVAL;
	}

	if (offset < len) {
		if (offset + size > len) size = len - offset;
		memcpy(buf, string + offset, size);
	} else size = 0;

	if (used_string) free(string);
	free(kv->data); free(kv);
	return size;
}


static int winregfs_write(const char *path, const char *buf,
		size_t size, off_t offset, struct fuse_file_info *fi)
{
	int nkofs;
	char node[ABSPATHLEN];
	char keypath[ABSPATHLEN];

	struct nk_key *key;
	int i, type;
	size_t newsize;
	char *newbuf = NULL;
	char *string = NULL;
	uint64_t val;  /* DWORD/QWORD hex string value */
	struct keyval *kv = NULL;
	struct keyval *newkv = NULL;

	LOAD_WD();

	DLOG("write: %s (%d + %d)\n", path, (int)size, (int)offset);

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
	if(!kv) {
		LOG("write: metadata missing for %s\n", path);
		return -ENOENT;
	}

	/******  TODO: Handle OFFSET!!! ******/
	/* Handle offset */
	newsize = offset + size;
	if(kv->len > newsize) newsize = kv->len;

	switch(type) {
	case REG_DWORD:
		i = find_nonhex(buf, 9);
		if (i < 1) {
			LOG("write: bad DWORD file format: %s\n", path);
			free(kv->data); free(kv);
			return -EINVAL;
		}
		i = convert_hex(buf, &val, i);
		LOG("3\n");
		if (i == -1) {
			LOG("write: bad DWORD file format: %s\n", path);
			free(kv->data); free(kv);
			return -EINVAL;
		}

		kv->len = 4;
		*((uint32_t *)kv->data) = (uint32_t)val;
		i = put_buf2val(wd->hive, kv, nkofs, node, type, TPF_VK_EXACT);

		if(!i) {
			LOG("write: error writing file: %s\n", path);
			free(kv->data); free(kv);
			return -EINVAL;
		}
		break;

	case REG_QWORD:
		i = find_nonhex(buf, 17);
		if(i < 1) {
			LOG("write: bad QWORD file format: %s\n", path);
			free(kv->data); free(kv);
			return -EINVAL;
		}
		i = convert_hex(buf, &val, i);
		if(i == -1) {
			LOG("write: bad QWORD file format: %s\n", path);
			free(kv->data); free(kv);
			return -EINVAL;
		}

		kv->len = 8;
		*((uint64_t *)kv->data) = val;
		i = put_buf2val(wd->hive, kv, nkofs, node, type, TPF_VK_EXACT);

		if(i) {
			LOG("write: error writing file: %s\n", path);
			free(kv->data); free(kv);
			return -EINVAL;
		}
		break;

	case REG_BINARY:
		newkv = (struct keyval *)malloc(sizeof(struct keyval));
		if(!newkv) {
			LOG("write: failed to allocate memory\n");
			free(kv->data); free(kv);
			return -ENOMEM;
		}

		ALLOC(newkv->data, 1, newsize);
		if(!newkv->data) {
			LOG("write: failed to allocate memory for buffer\n");
			free(newkv); free(kv->data); free(kv);
			return -ENOMEM;
		}

		memcpy(newkv->data, kv->data, kv->len);
		memcpy(((char *)newkv->data + offset), buf, size);
		newkv->len = newsize;
		i = put_buf2val(wd->hive, newkv, nkofs, node, type, TPF_VK_EXACT);
		free(newkv->data); free(newkv); free(kv->data); free(kv);

		if(!i) {
			LOG("write: error writing file: %s\n", path);
			return -EINVAL;
		}
		break;
	case REG_SZ:
	case REG_EXPAND_SZ:
	case REG_MULTI_SZ:
		newbuf = (char *)malloc(sizeof(char) * newsize);

		if(!newbuf) {
			LOG("write: failed to allocate memory for buffer\n");
			free(newbuf); free(kv->data); free(kv);
			return -ENOMEM;
		}

		if(offset != 0) {
			string = string_regw2prog(kv->data, kv->len);
			if(string == NULL) {
				LOG("write: out of memory\n");
				free(newbuf); free(kv->data); free(kv);
				return -ENOMEM;
			}
			memcpy(newbuf, string, kv->len >> 1);
			free(string);
		}
		newkv = (struct keyval *)malloc(sizeof(struct keyval));
		/* Extra byte for MULTI_SZ null termination */
		ALLOC(newkv->data, 1, (newsize + 1) << 1);

		memcpy((newbuf + offset), buf, size);
		newkv->len = newsize << 1;
		/* Truncate string at first non-ASCII char */
		if(type != REG_MULTI_SZ) {
			for(i = 0; i < newsize; i++) {
				if(newbuf[i] < 32) {
					newkv->len = i << 1;
					break;
				}
			}
		} else {
			/* MULTI_SZ is icky. Newlines become nulls! */
			for(i = 0; i < newsize; i++) {
				if(newbuf[i] < 32) newbuf[i] = '\0';
			}
		}

		cheap_ascii2uni(newbuf, (char *)newkv->data, newsize);
		i = put_buf2val(wd->hive, newkv, nkofs, node, type, TPF_VK_EXACT);
		free(newbuf); free(newkv->data); free(newkv); free(kv->data); free(kv);

		if(!i) {
			LOG("write: error writing file: %s\n", path);
			return -EINVAL;
		}
		break;
	default:
		LOG("write: type %d not supported: %s\n", type, path);
		free(newbuf); free(kv->data); free(kv);
		return -EINVAL;
		break;
	}

	if(writeHive(wd->hive)) {
		LOG("write: error writing changes to hive\n");
		errno = EPERM;
		free(newbuf); free(kv->data); free(kv);
		return -1;
	}

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

	nkofs = get_path_nkofs(wd, keypath, &key, 0);
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
#if ENABLE_NKOFS_CACHE
	get_path_nkofs(wd, keypath, &key, 1);
#endif
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

        nkofs = get_path_nkofs(wd, keypath, &key, 0);
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
#if ENABLE_NKOFS_CACHE
	get_path_nkofs(wd, keypath, &key, 1);
#endif
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

        nkofs = get_path_nkofs(wd, keypath, &key, 0);
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
#if ENABLE_NKOFS_CACHE
	get_path_nkofs(wd, keypath, &key, 1);
#endif
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

        nkofs = get_path_nkofs(wd, keypath, &key, 0);
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
#if ENABLE_NKOFS_CACHE
	get_path_nkofs(wd, keypath, &key, 1);
#endif
	return 0;
}


/* Timestamps not supported, just return success */
static int winregfs_utimens(const char *path, const struct timespec tv[2])
{
	LOAD_WD();
	LOG("Called but not implemented: utimens\n");
	return 0;
}


/* Truncate is stupid anyway */
static int winregfs_truncate(const char *path, off_t len)
{
	LOAD_WD();
	LOG("Called but not implemented: truncate (len %d)\n", (int)len);
	return 0;
}

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
	struct winregfs_data *wd;
	char file[ABSPATHLEN];
	int i;

	if ((argc < 3) || (argv[argc-2][0] == '-') || (argv[argc-1][0] == '-')) {
		fprintf(stderr, "Windows Registry Filesystem %s (%s)\n", VER, VERDATE);
		fprintf(stderr, "\nUsage: %s [options] hivename mountpoint\n\n", argv[0]);
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
	LOG("winregfs started\n");
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
