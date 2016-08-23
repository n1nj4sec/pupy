#ifndef TMPLIBRARY_H
#define TMPLIBRARY_H

#include <stdbool.h>

void *memdlopen(const char *soname, const char *buffer, size_t size, int flags);
bool drop_library(char *path, size_t path_size, const char *buffer, size_t size);

#endif /* TMPLIBRARY_H */
