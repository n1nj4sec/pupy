#define _GNU_SOURCE
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/mman.h>

#include "Python-dynload.h"

#define FREE_HMODULE_AFTER_LOAD 1
#define FILE_SYSTEM_ENCODING "utf-8"

typedef void *HMODULE;
typedef void* (*resolve_symbol_t) (HMODULE hModule, const char *name);

#ifndef OPENSSL_LIB_VERSION
	#define OPENSSL_LIB_VERSION "1.0.0"
#endif

#define DEPENDENCIES { \
		{ \
			"libcrypto.so." OPENSSL_LIB_VERSION, \
			libcrypto_c_start, libcrypto_c_size, FALSE \
		}, \
		{  \
			"libssl.so." OPENSSL_LIB_VERSION,  \
			libssl_c_start, libssl_c_size, FALSE \
		}, \
		{ \
			"libpython2.7.so.1.0", \
			python27_c_start, python27_c_size, TRUE \
		} \
	}

#define OSLoadLibary(name) dlopen(name, RTLD_NOW)
#define OSResolveSymbol dlsym
#define OSUnmapRegion munmap
#define MemLoadLibrary(name, bytes, size) \
	memdlopen(name, bytes, size, RTLD_NOW | RTLD_GLOBAL)
#define MemResolveSymbol dlsym
#define CheckLibraryLoaded(name) dlopen(name, RTLD_NOW | RTLD_NOLOAD)

#include "python27.c"
#include "libssl.c"
#include "libcrypto.c"

#include "tmplibrary.h"

