#ifndef __DEBUG_H
#define __DEBUG_H

#include <stdarg.h>

#ifdef DEBUG
static inline int dprint(const char *fmt, ...) {
	va_list args;
	va_start (args, fmt);
	int n = vfprintf(stderr, fmt, args);
	va_end (args);
	return n;
}

#else
#define dprint(...)							\
	do {} while (0)
#endif

#endif /* __DEBUG_H */
