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

#define UPDATE_INTERVAL 300

struct winregfs_data wd;

struct fsck_stat {
	int e_travpath;
	int e_nkofs;
	int e_read_key;
	int e_read_val;
	int w_type;
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
	return EXIT_SUCCESS;
}
/*** End helper functions ***/


void show_progress(struct fsck_stat *stats) {
	if (stats->update_delay > 0) {
		stats->update_delay--;
		return;
	} else stats->update_delay = UPDATE_INTERVAL;
	printf("Keys: %d  Values: %d  \r",
		stats->keys, stats->values);
	return;
}


static int process_key(struct fsck_stat *stats, const char *path, int depth, int verbose)
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
		if (verbose) printf("\rPath traversal failure: %s\n", keypath);
		stats->e_travpath++;
		return -1;
	}
	nkofs += 4;
	if(nkofs > wd.hive->size) {
		if (verbose) printf("\rNK offset too large: %s\n", keypath);
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
			error_count += process_key(stats, filename, depth, verbose);
		}
		if (i < 0) {
			if (verbose) printf("\rKey read failure: %s\n", keypath);
			stats->e_read_key++;
			show_progress(stats);
		}
	}

	count = 0;
	if (key->no_values) {
		while ((i = ex_next_v(wd.hive, nkofs, &count, &vex)) > 0) {
			stats->values++;
			show_progress(stats);
			if (vex.type > REG_MAX) {
				if (verbose) printf("\rValue type 0x%x is an unknown type: %s\n", vex.type, keypath);
				stats->w_type++;
			}
			strncpy(filename, keypath, ABSPATHLEN);
			strncat(filename, "\\", ABSPATHLEN);
			if (strlen(vex.name) == 0) strncpy(filename, "@", 2);
			else strncat(filename, vex.name, ABSPATHLEN);
			free(vex.name);
		}
		if (i < 0) {
			if (verbose) printf("\rValue read failure: %s\n", keypath);
			stats->e_read_val++;
			show_progress(stats);
		}
	}
	return EXIT_SUCCESS;

}


int main(int argc, char *argv[])
{
	char file[ABSPATHLEN];
	char path[ABSPATHLEN];
	int error_count, warn_count, verbose = 0;
	struct fsck_stat stats;

	if (argc == 2 && !strncasecmp(argv[1], "-v", 2)) {
		fprintf(stderr, "Windows Registry Hive File Checker %s (%s)\n", VER, VERDATE);
		return EXIT_SUCCESS;
	}
	if ((argc < 2) || (argv[argc-1][0] == '-')) {
		fprintf(stderr, "Windows Registry Hive File Checker %s (%s)\n", VER, VERDATE);
		fprintf(stderr, "\nUsage: %s [options] hivename\n\n", argv[0]);
		return EXIT_FAILURE;
	}

	if (!strncmp(argv[1], "-v", 3)) {
		printf("Verbose mode enabled\n");
		verbose = 1;
	}

	/* Pull hive file name from command line */
	strncpy(file, argv[argc-1], ABSPATHLEN);

	/* malloc() and initialize cache pointers/data */
	wd.hive = openHive(file, HMODE_RW);
	if (!wd.hive) {
		fprintf(stderr, "Error: couldn't open %s\n", file);
		return EXIT_FAILURE;
	}

	stats.e_travpath = 0;
	stats.e_nkofs = 0;
	stats.e_read_key = 0;
	stats.e_read_val = 0;
	stats.w_type = 0;
	stats.keys = 0;
	stats.values = 0;
	stats.maxdepth = 0;
	stats.update_delay = 0;
	/* Start at the hive root */
	path[0] = '\\'; path[1] = '\0';
	process_key(&stats, path, -1, verbose);
	closeHive(wd.hive);
	error_count = (stats.e_travpath +
			stats.e_nkofs +
			stats.e_read_key +
			stats.e_read_val);
	warn_count = (stats.w_type);
	/* Show final stats for everything */
	printf("Keys: %d   Values: %d   Max key depth: %d\n", stats.keys, stats.values, stats.maxdepth);
	if (stats.e_travpath)
	printf("\nPath traversal errors: %d\n", stats.e_travpath);
	if (stats.e_nkofs)
	printf("\n'nk' offset errors:    %d\n", stats.e_nkofs);
	if (stats.e_read_key)
	printf("\nKey read errors:       %d\n", stats.e_read_key);
	if (stats.e_read_val)
	printf("\nValue read errors:     %d\n", stats.e_read_val);
	if (stats.w_type)
	printf("\nValue type warnings:   %d\n", stats.w_type);
	if (error_count || warn_count) {
		printf("\nHive %s has ", file);
		if (error_count) {
			printf("%d total errors", error_count);
			if (warn_count) printf(" and ");
		}
		if (warn_count) printf("%d total warnings", warn_count);
		printf("\n\n");
	} else printf("Hive %s is clean.\n\n", file);
	return (error_count ? EXIT_FAILURE : EXIT_SUCCESS);
}
