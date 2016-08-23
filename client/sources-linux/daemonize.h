#ifndef DAEMONIZE_H
#define DAEMONIZE_H

#include <unistd.h>
#include <stdbool.h>

pid_t daemonize(bool exit_parent);

#endif /* DAEMONIZE_H */
