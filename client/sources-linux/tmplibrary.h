#ifndef TMPLIBRARY_H
#define TMPLIBRARY_H

#include <sys/types.h>
#include <stdbool.h>

void *memdlopen(const char *soname, const char *buffer, size_t size, bool compressed);
bool drop_library(char *path, size_t path_size, const char *buffer, size_t size, bool compressed);

#endif /* TMPLIBRARY_H */
