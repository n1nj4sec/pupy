#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <linux/fs.h>

#include "daemonize.h"

int daemonize(bool exit_parent) {
    pid_t pid;
    int i;

	int pipes[2];

	if (!exit_parent) {
		if (pipe(pipes) == -1) {
			return -1;
		}
	}

    /* create new process */
    pid = fork ( );
    if (pid == -1)
        return -1;

    else if (pid != 0) {
		if (exit_parent) {
			exit (EXIT_SUCCESS);
		} else {
			int status;
			waitpid(pid, &status, 0);
			if (read(pipes[0], &pid, sizeof(pid)) != sizeof(pid))
				pid = -1;

			return pid;
		}
	}

	/* Fork once again */
    pid = fork ( );
    if (pid == -1) {
		if (!exit_parent) {
			close(pipes[1]);
		}

        return -1;
	}

    else if (pid != 0) {
		exit (EXIT_SUCCESS);
	}

	if (!exit_parent) {
		pid_t current_pid = getpid();
		write(pipes[1], &current_pid, sizeof(current_pid));
		close(pipes[1]);
	}

    /* create new session and process group */
    if (setsid ( ) == -1)
        return -1;

    /* set the working directory to the root directory */
    if (chdir ("/") == -1)
        return -1;

    /* close all open files--NR_OPEN is overkill, but works */
    for (i = 0; i < sysconf(_SC_OPEN_MAX); i++)
        close (i);

#ifndef DEBUG
    /* redirect fd's 0,1,2 to /dev/null */
    open ("/dev/null", O_RDWR);
    /* stdin */
    dup (0);
    /* stdout */
    dup (0);
    /* stderror */
#endif

    /* do its daemon thing... */
	return 0;
}
