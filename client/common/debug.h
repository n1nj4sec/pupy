#ifndef __DEBUG_H
#define __DEBUG_H

#include <stdio.h>
#include <stdarg.h>

#ifdef DEBUG

int dprint(const char *fmt, ...);
void set_debug_log(const char *dest);

#define DOC(x) x

#else
#define DOC(x) ""

#define dprint(...)	do {} while (0)

#endif

#endif /* __DEBUG_H */
