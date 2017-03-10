#ifndef DAEMONIZE_H
#define DAEMONIZE_H

#include <unistd.h>
#include <stdbool.h>
#include <sys/types.h>

pid_t daemonize(int argc, char *argv[], char *env[], bool exit_parent);

#endif /* DAEMONIZE_H */
