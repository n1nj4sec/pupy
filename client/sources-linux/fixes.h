#ifndef ___FIXES_H
#define ___FIXES_H


#include <sys/ptrace.h>

#ifndef PTRACE_GETSIGINFO
#define PTRACE_GETSIGINFO 0x4202
#endif

static inline
char *realpath2(const char *path, char *resolved_path) {
	return path;
}

#endif
