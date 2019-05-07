#ifndef ___FIXES_H
#define ___FIXES_H

#include <linux/limits.h>
#include <string.h>
#include <sys/ptrace.h>

#ifndef PTRACE_GETSIGINFO
#define PTRACE_GETSIGINFO 0x4202
#endif

#ifndef EM_AARCH64
#define EM_AARCH64		183
#endif

#endif
