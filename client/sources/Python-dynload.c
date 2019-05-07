/* **************** Python-dynload.c **************** */
#include "Python-dynload.h"
#include <windows.h>
#include "MyLoadLibrary.h"
#include "MemoryModule.h"
#include "actctx.h"
#include <stdio.h>
#include "debug.h"

#ifndef UINTPTR
 #ifndef _WIN32
   typedef DWORD UINTPTR;
 #else
   typedef ULONGLONG UINTPTR;
 #endif
#endif

struct IMPORT imports[] = {
#include "import-tab.c"
	{ NULL, NULL }, /* sentinel */
};

#ifndef PY_INCREF
#define PY_INCREF Py_IncRef
#endif

#ifndef PY_DECREF
#define PY_DECREF Py_DecRef
#endif

#ifndef Py_XINCREF
#define Py_XINCREF(op) do { if ((op) == NULL) ; else Py_INCREF(op); } while (0)
#endif

#ifndef Py_XDECREF
#define Py_XDECREF(op) do { if ((op) == NULL) ; else Py_DECREF(op); } while (0)
#endif

int _load_python_FromFile(char *dllname)
{
	int i;
	struct IMPORT *p = imports;
	HMODULE hmod;

	// In some cases (eg, ISAPI filters), Python may already be
	// in our process.  If so, we don't want it to try and
	// load a new one!  (Actually, we probably should not even attempt
	// to load an 'embedded' Python should GetModuleHandle work - but
	// that is less clear than this straight-forward case)
	// Get the basename of the DLL.
	char *dllbase = dllname + strlen(dllname);
	while (dllbase != dllname && *dllbase != '\\')
		dllbase--;
	if (*dllbase=='\\')
		++dllbase;
	hmod = GetModuleHandle(dllbase);
	if (hmod == NULL)
		hmod = LoadLibrary(dllname);
	if (hmod == NULL) {
		return 0;
	}

	for (i = 0; p->name; ++i, ++p) {
		p->proc = (void (*)())GetProcAddress(hmod, p->name);
		if (p->proc == NULL) {
			OutputDebugString("undef symbol");
			dfprint(stderr, "undefined symbol %s -> exit(-1)\n", p->name);
			return 0;
		}
	}

	return 1;
}

UINTPTR _load_dll(const char *name, const char *bytes){

	HMODULE hmod;
	ULONG_PTR cookie = 0;
	cookie = _My_ActivateActCtx();
	hmod = MyLoadLibrary(name, bytes, NULL);
	_My_DeactivateActCtx(cookie);
	return hmod;
}

HMODULE _load_msvcr90(char *bytes)
{
	return _load_dll("msvcr90.dll", bytes);
}

int _load_python(char *dllname, char *bytes)
{
	int i;
	struct IMPORT *p = imports;
	HMODULE hmod;
	ULONG_PTR cookie = 0;
	if (!bytes)
		return _load_python_FromFile(dllname);


	cookie = _My_ActivateActCtx();//try some windows manifest magic...
	//hmod = MemoryLoadLibrary(bytes);
	hmod = MyLoadLibrary(dllname, bytes, NULL);
	_My_DeactivateActCtx(cookie);
	if (hmod == NULL) {
		return 0;
	}

	for (i = 0; p->name; ++i, ++p) {
		//p->proc = (void (*)())MemoryGetProcAddress(hmod, p->name);
		p->proc = (void (*)())MyGetProcAddress(hmod, p->name);
		if (p->proc == NULL) {
			OutputDebugString("undef symbol");
			dfprint(stderr, "undefined symbol %s -> exit(-1)\n", p->name);
			return 0;
		}
	}

	return 1;
}
