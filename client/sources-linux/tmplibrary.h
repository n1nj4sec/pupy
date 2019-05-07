#ifndef TMPLIBRARY_H
#define TMPLIBRARY_H

#define _GNU_SOURCE
#include <dlfcn.h>

#include <sys/types.h>
#include <stdbool.h>

#include <link.h>

#ifndef RTLD_DI_LINKMAP
#define RTLD_DI_LINKMAP 2
#endif

int _dlinfo(void *handle, int request, void *info);

void *memdlopen(const char *soname, const char *buffer, size_t size, int flags);
int drop_library(char *path, size_t path_size, const char *buffer, size_t size);
pid_t memexec(const char *buffer, size_t size, const char *const* argv, int stdior[3],
              bool redirected_stdio, bool detach);

int remap(const char *path);

#endif /* TMPLIBRARY_H */
