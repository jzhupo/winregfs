/*
 * Jody Bruchon's string function library
 *
 * Copyright (C) 2015-2021 by Jody Bruchon <jody@jodybruchon.com>
 * See jody_string.c for license information
 */

#ifndef JODY_STRING_H
#define JODY_STRING_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <unistd.h>

extern int strncaseeq(const char *s1, const char *s2, size_t len);
extern int strcaseeq(const char *s1, const char *s2);
extern int strneq(const char *s1, const char *s2, size_t len);
extern int streq(const char *s1, const char *s2);


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
