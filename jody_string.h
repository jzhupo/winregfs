/*
 * Jody Bruchon's string function library  <jody@jodybruchon.com>
 * Copyright (C) 2015-2016
 * Distributed under the GNU General Public License version 2
 */

#ifndef JODY_STRING_H
#define JODY_STRING_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <unistd.h>

int strncaseeq(const char *s1, const char *s2, size_t len);
int strcaseeq(const char *s1, const char *s2);
int strneq(const char *s1, const char *s2, size_t len);
int streq(const char *s1, const char *s2);


/* Inline strcpy() */
inline void xstrcpy(char * restrict dest, const char * restrict src)
{
        while (*src != '\0') {
                *dest = *src;
                dest++; src++;
        }
        *dest = '\0';
}

#ifdef __cplusplus
}
#endif

#endif /* JODY_STRING_H */
