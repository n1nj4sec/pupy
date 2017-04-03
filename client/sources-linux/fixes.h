#ifndef ___FIXES_H
#define ___FIXES_H

#include <linux/limits.h>
#include <string.h>
#include <sys/ptrace.h>

#ifndef PTRACE_GETSIGINFO
#define PTRACE_GETSIGINFO 0x4202
#endif

static inline
char *fakepath(const char *path, char *resolved_path) {
	if (resolved_path) {
		strncpy(resolved_path, path, PATH_MAX);
		return resolved_path;
	} else {
		return strdup(path);
	}
}

#endif
