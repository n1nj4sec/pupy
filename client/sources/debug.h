#ifndef __DEBUG_H
#define __DEBUG_H

#include <stdio.h>
#include <stdarg.h>

#ifdef DEBUG

static int dprint(const char *fmt, ...) {
	va_list args;
    int n;

	va_start (args, fmt);
	n = vfprintf(stderr, fmt, args);
	va_end (args);
	return n;
}

static int dfprint(FILE *stream, const char *fmt, ...) {
	va_list args;
    int n;

	va_start (args, fmt);
	n = vfprintf(stream, fmt, args);
	va_end (args);
	return n;
}

#else

#define dprint(...)	do {} while (0)
#define dfprint(...) do {} while (0)

#endif

#endif /* __DEBUG_H */
