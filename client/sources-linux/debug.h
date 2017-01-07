#ifndef __DEBUG_H
#define __DEBUG_H

#include <stdio.h>
#include <stdarg.h>

#ifdef DEBUG

static inline int dprint(const char *fmt, ...) {
	va_list args;
	va_start (args, fmt);
	int n = vfprintf(stderr, fmt, args);
	va_end (args);
	return n;
}

static inline int dfprint(FILE *stream, const char *fmt, ...) {
	va_list args;
	va_start (args, fmt);
	int n = vfprintf(stream, fmt, args);
	va_end (args);
	return n;
}

#else

#define dprint(...)	do {} while (0)
#define dfprint(...) do {} while (0)

#ifdef printf
#undef printf
#endif

#ifdef fprintf
#undef fprintf
#endif

#define printf(...)	do {} while (0)
#define fprintf(...) do {} while (0)

#endif

static inline
void dexit(int status) {}

#endif /* __DEBUG_H */
