/*
 * Jody Bruchon's string function library  <jody@jodybruchon.com>
 * Copyright (C) 2015-2020
 * Released under The MIT License
 */

#include <stdint.h>
#include <unistd.h>

/* Like strncasecmp() but only tests for equality */
extern int strncaseeq(const char *s1, const char *s2, size_t len)
{
	size_t i = 0;

	while (i < len) {
		if (*s1 != *s2) {
			unsigned char c1, c2;

			c1 = *(const unsigned char *)s1;
			c2 = *(const unsigned char *)s2;
			/* Transform upper case to lower case */
			if (c1 == 0 || c2 == 0) return 1;
			if (c1 >= 'A' && c1 <= 'Z') c1 |= 0x20;
			if (c2 >= 'A' && c2 <= 'Z') c2 |= 0x20;
			if (c1 != c2) return 1;
		} else {
			if (*s1 == 0) return 0;
		}
		s1++; s2++;
		i++;
	}
	return 0;
}

/* Like strcasecmp() but only tests for equality */
extern int strcaseeq(const char *s1, const char *s2)
{
	while (1) {
		if (*s1 != *s2) {
			unsigned char c1, c2;

			c1 = *(const unsigned char *)s1;
			c2 = *(const unsigned char *)s2;
			/* Transform upper case to lower case */
			if (c1 == 0 || c2 == 0) return 1;
			if (c1 >= 'A' && c1 <= 'Z') c1 |= 0x20;
			if (c2 >= 'A' && c2 <= 'Z') c2 |= 0x20;
			if (c1 != c2) return 1;
		} else {
			if (*s1 == 0) return 0;
		}
		s1++; s2++;
	}
	return 1;
}


/* Like strncmp() but only tests for equality */
extern int strneq(const char *s1, const char *s2, size_t len)
{
	size_t i = 0;

	if (!len) return 0;

	while (*s1 != '\0' && *s2 != '\0') {
		if (*s1 != *s2) return 1;
		s1++; s2++; i++;
		if (i == len) return 0;
	}
	if (*s1 != *s2) return 1;
	return 0;
}


/* Like strcmp() but only tests for equality */
extern int streq(const char *s1, const char *s2)
{
	while (*s1 != '\0' && *s2 != '\0') {
		if (*s1 != *s2) return 1;
		s1++; s2++;
	}
	if (*s1 != *s2) return 1;
	return 0;
}


