#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <stdarg.h>
#include <sys/types.h>
#include <errno.h>

#include "debug.h"
#include "ld_hooks.h"

#define export __attribute__((visibility("default")))

static int (*global_open)(const char *pathname, int flags, ...) = NULL;
static int (*global_open64)(const char *pathname, int flags, ...) = NULL;
static int (*global_openat)(int dirfd, const char *pathname, int flags, ...) = NULL;
static int (*global_openat64)(int dirfd, const char *pathname, int flags, ...) = NULL;
static FILE *(*global_fopen)(const char *pathname, const char *mode) = NULL;
static FILE *(*global_fopen64)(const char *pathname, const char *mode) = NULL;

static int (*global__lxstat)(int ver, const char * path, struct stat* stat_buf) = NULL;
static int (*global__xstat)(int ver, const char * path, struct stat * stat_buf) = NULL;
static int (*global__lxstat64)(int ver, const char * path, struct stat64 * stat_buf) = NULL;
static int (*global__xstat64)(int ver, const char * path, struct stat64 * stat_buf) = NULL;

static cb_hooks_t __pathmap_callback = NULL;

#ifndef O_TMPFILE
#define O_TMPFILE 020000000
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#ifdef _LD_HOOKS_NAME
export
#endif
void set_pathmap_callback(cb_hooks_t cb)
{
    __pathmap_callback = cb;
    dprint("ldhooks:set_callback(%p)\n", __pathmap_callback);
}

#define define_mapped_path(mapped_path, path) \
    char buf[PATH_MAX] = {};                  \
    const char *mapped_path = __pathmap_callback? \
        __pathmap_callback(path, buf, sizeof(buf)) : path

export int __lxstat(int ver, const char * path, struct stat* stat_buf)
{
    define_mapped_path(mapped_path, path);

    dprint("ldhooks:__lxstat(%d, %s (%s), %p) @ %p\n", ver, path, mapped_path,
        stat_buf, __pathmap_callback);

    if (!global__lxstat || !mapped_path) {
        errno = ENOENT;
        return -1;
    }

    return global__lxstat(ver, mapped_path, stat_buf);
}

export int __lxstat64(int ver, const char * path, struct stat64* stat_buf)
{
    define_mapped_path(mapped_path, path);

    dprint("ldhooks:__lxstat64(%d, %s (%s), %p) @ $p\n", ver, path,
        mapped_path, stat_buf, __pathmap_callback);
    if (!global__lxstat || !mapped_path) {
        errno = ENOENT;
        return -1;
    }

    return global__lxstat64(ver, mapped_path, stat_buf);
}

export int __xstat(int ver, const char * path, struct stat* stat_buf)
{
    define_mapped_path(mapped_path, path);

    dprint("ldhooks:__xstat(%d, %s (%s), %p)\n", ver, path, mapped_path, stat_buf);
    if (!global__xstat || !mapped_path) {
        errno = ENOENT;
        return -1;
    }

    return global__xstat(ver, mapped_path, stat_buf);
}

export int __xstat64(int ver, const char * path, struct stat64* stat_buf)
{
    define_mapped_path(mapped_path, path);

    dprint("ldhooks:__xstat64(%d, %s (%s), %p)\n", ver, path, mapped_path, stat_buf);
    if (!global__xstat) {
        errno = ENOENT;
        return -1;
    }

    return global__xstat64(ver, mapped_path, stat_buf);
}

export int open(const char *pathname, int flags, ...)
{
    int ret = -1;
    va_list args;
    va_start(args, flags);
    define_mapped_path(mapped_path, pathname);

    dprint("ldhooks:open(%s (%s), %08x)\n", pathname, mapped_path, flags);

    if (!global_open || !mapped_path) {
        errno = ENOENT;
    } else {
        if (flags & (O_CREAT | O_TMPFILE)) {
            mode_t mode = va_arg(args, mode_t);
            ret = global_open(mapped_path, flags, mode);
        } else {
            ret = global_open(mapped_path, flags);
        }
    }

    va_end(args);
    return ret;
}

export int open64(const char *pathname, int flags, ...)
{
    int ret = -1;
    va_list args;
    va_start(args, flags);
    define_mapped_path(mapped_path, pathname);

    dprint("ldhooks:open64(%s (%s), %08x)\n", pathname, mapped_path, flags);

    if (!global_open64 || !mapped_path) {
        errno = ENOENT;
    } else {
        if (flags & (O_CREAT | O_TMPFILE)) {
            mode_t mode = va_arg(args, mode_t);
            ret = global_open64(mapped_path, flags, mode);
        } else {
            ret = global_open64(mapped_path, flags);
        }
    }

    va_end(args);
    return ret;
}

export int openat(int dirfd, const char *pathname, int flags, ...)
{
    int ret = -1;
    va_list args;
    va_start(args, flags);
    define_mapped_path(mapped_path, pathname);

    dprint("ldhooks:openat(%d, %s (%s), %08x)\n", dirfd, mapped_path, pathname, flags);

    if (!global_openat || !mapped_path) {
        errno = ENOENT;
    } else {
        if (flags & (O_CREAT | O_TMPFILE)) {
            mode_t mode = va_arg(args, mode_t);
            ret = global_openat(dirfd, mapped_path, flags, mode);
        } else {
            ret = global_openat(dirfd, mapped_path, flags);
        }
    }

    va_end(args);
    return ret;
}

export int openat64(int dirfd, const char *pathname, int flags, ...)
{
    int ret = -1;
    va_list args;
    va_start(args, flags);
    define_mapped_path(mapped_path, pathname);

    dprint("ldhooks:openat64(%d, %s (%s), %08x)\n", dirfd, pathname, mapped_path, flags);

    if (!global_openat64 || !mapped_path) {
        errno = ENOENT;
    } else {
        if (flags & (O_CREAT | O_TMPFILE)) {
            mode_t mode = va_arg(args, mode_t);
            ret = global_openat64(dirfd, mapped_path, flags, mode);
        } else {
            ret = global_openat64(dirfd, mapped_path, flags);
        }
    }

    va_end(args);
    return ret;
}

export FILE *fopen(const char *pathname, const char *mode)
{
    define_mapped_path(mapped_path, pathname);

    dprint("ldhooks:fopen(%s (%s), %s)\n", pathname, mapped_path, mode);

    if (!global_fopen || !mapped_path) {
        errno = ENOENT;
        return NULL;
    }

    return global_fopen(mapped_path, mode);
}

export FILE *fopen64(const char *pathname, const char *mode)
{
    define_mapped_path(mapped_path, pathname);
    dprint("ldhooks:fopen64(%s (%s), %s) @ %p\n", pathname,
        mapped_path, mode, __pathmap_callback);

    if (!global_fopen64 || !mapped_path) {
        errno = ENOENT;
        return NULL;
    }

    return global_fopen64(mapped_path, mode);
}

#ifdef _LD_HOOKS_NAME
static
#endif
void _ld_hooks_main(int argc, char *argv[], char *envp[])
{
    dprint("ldhooks: initialize targets\n");

    global_fopen = dlsym(RTLD_NEXT, "fopen");
    global_fopen64 = dlsym(RTLD_NEXT, "fopen64");
    global_open = dlsym(RTLD_NEXT, "open");
    global_open64 = dlsym(RTLD_NEXT, "open64");
    global_openat = dlsym(RTLD_NEXT, "openat");
    global_openat64 = dlsym(RTLD_NEXT, "openat64");
    global__lxstat64 = dlsym(RTLD_NEXT, "__lxstat64");
    global__lxstat = dlsym(RTLD_NEXT, "__lxstat");
    global__xstat64 = dlsym(RTLD_NEXT, "__xstat64");
    global__xstat = dlsym(RTLD_NEXT, "__xstat");
}

#ifdef _LD_HOOKS_NAME
__attribute__((section(".init_array"))) void (*ld_hooks_main)(int, char *[], char *[]) = _ld_hooks_main;
#endif
