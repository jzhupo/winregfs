/*
 * Windows registry "filesystem checker"
 *
 * Written by Jody Bruchon <jody@jodybruchon.com> 2014-04-20
 *
 * Licensed under GNU GPL v2. See LICENSE and README for details.
 *
 */

#define _FSCK_

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
#include "ntreg.h"
#include "winregfs.h"

struct winregfs_data wd;

struct fsck_stat {
	int e_travpath;
	int e_nkofs;
	int e_read_key;
	int e_read_val;
	int e_type;
	int keys;
	int values;
	int maxdepth;
	int update_delay;
};

void invalidate_cache(void) {
	return;
}

/* Converts a path to the required formats for keypath/nodepath usage */
static inline int sanitize_path(const char *path, char *keypath, char *node)
{
	strncpy(keypath, path, ABSPATHLEN);
	strncpy(node, path, ABSPATHLEN);
	dirname(keypath);   /* need to read the root key */
	strncpy(node, basename(node), ABSPATHLEN); 
	return 0;
}
/*** End helper functions ***/


void show_progress(struct fsck_stat *stats) {
	if (stats->update_delay > 0) {
		stats->update_delay--;
		return;
	} else stats->update_delay = 1000;
	printf("Keys: %d    Values: %d  \r",
		stats->keys, stats->values);
	return;
}


static int process_key(struct fsck_stat *stats, const char *path, int depth)
{
/*
 * For keys, run process_key again recursively
 * For values, just check that the value exists for now
 */
	struct nk_key *key;
	int nkofs, i;
	struct ex_data ex;
	struct vex_data vex;
	int count = 0, countri = 0, error_count = 0;
	char filename[ABSPATHLEN];
	char keypath[ABSPATHLEN];

	depth++;
	if (stats->maxdepth < depth) stats->maxdepth = depth;
	stats->keys++;
	show_progress(stats);
	strncpy(keypath, path, ABSPATHLEN);

	nkofs = trav_path(wd.hive, 0, keypath, TPF_NK_EXACT);
	if (!nkofs) {
		stats->e_travpath++;
		return -1;
	}
	nkofs += 4;
	if(nkofs > wd.hive->size) {
		stats->e_nkofs++;
		return -1;
	}
	key = (struct nk_key *)(wd.hive->buffer + nkofs);

	if (key->no_subkeys) {
		while ((i = ex_next_n(wd.hive, nkofs, &count, &countri, &ex)) > 0) {
			strncpy(filename, keypath, ABSPATHLEN);
			if(strncmp(keypath, "\\", 3)) strncat(filename, "\\", ABSPATHLEN);
			strncat(filename, ex.name, ABSPATHLEN);
			free(ex.name);
			error_count += process_key(stats, filename, depth);
		}
		if (i < 0) stats->e_read_key++;
	}

	count = 0;
	if (key->no_values) {
		while ((i = ex_next_v(wd.hive, nkofs, &count, &vex)) > 0) {
			stats->values++;
			show_progress(stats);
			if (vex.type > REG_MAX) stats->e_type++;
			strncpy(filename, keypath, ABSPATHLEN);
			strncat(filename, "\\", ABSPATHLEN);
			if (strlen(vex.name) == 0) strncpy(filename, "@", 2);
			else strncat(filename, vex.name, ABSPATHLEN);
			free(vex.name);
		}
		if (i < 0) stats->e_read_val++;
	}
	return 0;

}


int main(int argc, char *argv[])
{
	char file[ABSPATHLEN];
	char path[ABSPATHLEN];
	int error_count;
	struct fsck_stat stats;

	fprintf(stderr, "Windows Registry Hive File Checker %s (%s)\n", VER, VERDATE);
	if ((argc < 2) || (argv[argc-1][0] == '-')) {
		fprintf(stderr, "\nUsage: %s [options] hivename\n\n", argv[0]);
		return 1;
	}

	/* Pull hive file name from command line */
	strncpy(file, argv[argc-1], ABSPATHLEN);
	fprintf(stderr, "Scanning hive %s\n", file);

	/* malloc() and initialize cache pointers/data */
	wd.hive = openHive(file, HMODE_RW);
	if (!wd.hive) {
		fprintf(stderr, "Error: couldn't open %s\n", file);
		return 1;
	}

	stats.e_travpath = 0;
	stats.e_nkofs = 0;
	stats.e_read_key = 0;
	stats.e_read_val = 0;
	stats.e_type = 0;
	stats.keys = 0;
	stats.values = 0;
	stats.maxdepth = 0;
	stats.update_delay = 0;
	/* Start at the hive root */
	path[0] = '\\'; path[1] = '\0';
	process_key(&stats, path, -1);
	closeHive(wd.hive);
	error_count = (stats.e_travpath +
			stats.e_nkofs +
			stats.e_read_key +
			stats.e_read_val +
			stats.e_type);
	/* Show final stats for everything */
	printf("                                                     \n");
	printf("Number of keys:        %d\n", stats.keys);
	printf("Number of values:      %d\n", stats.values);
	printf("Maximum key depth:     %d\n", stats.maxdepth);
	printf("\n");
	printf("Path traversal errors: %d\n", stats.e_travpath);
	printf("'nk' offset errors:    %d\n", stats.e_nkofs);
	printf("Key read errors:       %d\n", stats.e_read_key);
	printf("Value read errors:     %d\n", stats.e_read_val);
	printf("Key type errors:       %d\n", stats.e_type);
	printf("-------------------------\n");       
	printf("Total hive errors:     %d\n\n", error_count);
	return (error_count ? 1 : 0);
}
