#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include "memfd.h"

char *__real_realpath(const char *path, char *resolved_path);

char *__wrap_realpath(const char *path, char *resolved_path) {
        if (is_memfd_path(path)) {
                memcpy(resolved_path, path, strlen(path) + 1);
                return resolved_path;
        }

        return __real_realpath(path, resolved_path);
}
