#ifndef TMPLIBRARY_H
#define TMPLIBRARY_H

#include <sys/types.h>
#include <stdbool.h>

void *memdlopen(const char *soname, const char *buffer, size_t size);
int drop_library(char *path, size_t path_size, const char *buffer, size_t size);
pid_t memexec(const char *buffer, size_t size, const char *const* argv, int stdior[3],
              bool redirected_stdio, bool detach);

#endif /* TMPLIBRARY_H */
