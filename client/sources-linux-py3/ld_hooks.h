#ifndef LD_HOOKS_H
#define LD_HOOKS_H

#include <sys/types.h>

typedef const char * (*cb_hooks_t)(const char *path, char *buf, size_t buf_size);
void set_pathmap_callback(cb_hooks_t cb);

#ifndef _LD_HOOKS_NAME
void _ld_hooks_main(int argc, char *argv[], char *envp[]);
#endif

#endif
