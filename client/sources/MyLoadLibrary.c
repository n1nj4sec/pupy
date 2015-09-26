//#define VERBOSE
#ifdef STANDALONE
#  include <Python.h>
#  include "Python-version.h"
#else
#  include "Python-dynload.h"
#  include <stdio.h>
#endif
#include <windows.h>

#include "MemoryModule.h"
#include "MyLoadLibrary.h"

//#define VERBOSE /* enable to print debug output */

/*

Windows API:
============

HMODULE LoadLibraryA(LPCSTR)
HMODULE GetModuleHandleA(LPCSTR)
BOOL FreeLibrary(HMODULE)
FARPROC GetProcAddress(HMODULE, LPCSTR)


MemoryModule API:
=================

HMEMORYMODULE MemoryLoadLibrary(void *)
void MemoryFreeLibrary(HMEMORYMODULE)
FARPROC MemoryGetProcAddress(HMEMORYMODULE, LPCSTR)

HMEMORYMODULE MemoryLoadLibrayEx(void *,
                                 load_func, getproc_func, free_func, userdata)

(there are also some resource functions which are not used here...)

General API in this file:
=========================

HMODULE MyLoadLibrary(LPCSTR, void *, userdata)
HMODULE MyGetModuleHandle(LPCSTR)
BOOL MyFreeLibrary(HMODULE)
FARPROC MyGetProcAddress(HMODULE, LPCSTR)

 */

/****************************************************************
 * A linked list of loaded MemoryModules.
 */
typedef struct tagLIST {
	HCUSTOMMODULE module;
	LPCSTR name;
	struct tagLIST *next;
	struct tagLIST *prev;
	int refcount;
} LIST;

static LIST *libraries;

int level;

static int dprintf(char *fmt, ...)
{
#ifdef VERBOSE
	va_list marker;
	int i;
	
	va_start(marker, fmt);
	for (i = 0; i < level; ++i) {
		putchar(' ');
		putchar(' ');
	}
	return vfprintf(stderr, fmt, marker) + 2*level;
#else
	return 0;
#endif
}

#define PUSH() level++
#define POP()  level--

/****************************************************************
 * Search for a loaded MemoryModule in the linked list, either by name
 * or by module handle.
 */
static LIST *_FindMemoryModule(LPCSTR name, HMODULE module)
{
	LIST *lib = libraries;
	while (lib) {
		if (name && 0 == _stricmp(name, lib->name)) {
			dprintf("_FindMemoryModule(%s, %p) -> %s[%d]\n", name, module, lib->name, lib->refcount);
			return lib;
		} else if (module == lib->module) {
			dprintf("_FindMemoryModule(%s, %p) -> %s[%d]\n", name, module, lib->name, lib->refcount);
			return lib;
		} else {
			lib = lib->next;
		}
	}
	return NULL;
}

/****************************************************************
 * Insert a MemoryModule into the linked list of loaded modules
 */
static LIST *_AddMemoryModule(LPCSTR name, HCUSTOMMODULE module)
{
	LIST *entry = (LIST *)malloc(sizeof(LIST));
	entry->name = _strdup(name);
	entry->module = module;
	entry->next = libraries;
	entry->prev = NULL;
	entry->refcount = 1;
	libraries = entry;
	dprintf("_AddMemoryModule(%s, %p) -> %p[%d]\n",
		name, module, entry, entry->refcount);
	return entry;
}

/****************************************************************
 * Helper functions for MemoryLoadLibraryEx
 */
static FARPROC _GetProcAddress(HCUSTOMMODULE module, LPCSTR name, void *userdata)
{
	return MyGetProcAddress(module, name);
}

static void _FreeLibrary(HCUSTOMMODULE module, void *userdata)
{
	MyFreeLibrary(module);
}

static HCUSTOMMODULE _LoadLibrary(LPCSTR filename, void *userdata)
{
	HCUSTOMMODULE result;
	LIST *lib;
	dprintf("_LoadLibrary(%s, %p)\n", filename, userdata);
	PUSH();
	lib = _FindMemoryModule(filename, NULL);
	if (lib) {
		lib->refcount += 1;
		POP();
		dprintf("_LoadLibrary(%s, %p) -> %s[%d]\n\n",
			filename, userdata, lib->name, lib->refcount);
		return lib->module;
	}
	if (userdata) {
		PyObject *findproc = (PyObject *)userdata;
		PyObject *res = PyObject_CallFunction(findproc, "s", filename);
		if (res && PyString_AsString(res)) {
			result = MemoryLoadLibraryEx(PyString_AsString(res),
						     _LoadLibrary, _GetProcAddress, _FreeLibrary,
						     userdata);
			Py_DECREF(res);
			if (result) {
				lib = _AddMemoryModule(filename, result);
				POP();
				dprintf("_LoadLibrary(%s, %p) -> %s[%d]\n\n",
					filename, userdata, lib->name, lib->refcount);
				return lib->module;
			} else {
				dprintf("_LoadLibrary(%s, %p) failed with error %d\n",
					filename, userdata, GetLastError());
			}
		} else {
			PyErr_Clear();
		}
	}
	result = (HCUSTOMMODULE)LoadLibraryA(filename);
	POP();
	dprintf("LoadLibraryA(%s) -> %p\n\n", filename, result);
	return result;
}

/****************************************************************
 * Public functions
 */
HMODULE MyGetModuleHandle(LPCSTR name)
{
	LIST *lib;
	lib = _FindMemoryModule(name, NULL);
	if (lib)
		return lib->module;
	return GetModuleHandle(name);
}

HMODULE MyLoadLibrary(LPCSTR name, void *bytes, void *userdata)
{
	if (userdata) {
		HCUSTOMMODULE mod = _LoadLibrary(name, userdata);
		if (mod)
			return mod;
	} else if (bytes) {
		HCUSTOMMODULE mod = MemoryLoadLibraryEx(bytes,
							_LoadLibrary,
							_GetProcAddress,
							_FreeLibrary,
							userdata);
		if (mod) {
			LIST *lib = _AddMemoryModule(name, mod);
			return lib->module;
		}
	}
	return LoadLibrary(name);
}

BOOL MyFreeLibrary(HMODULE module)
{
	LIST *lib = _FindMemoryModule(NULL, module);
	if (lib) {
		if (--lib->refcount == 0)
			MemoryFreeLibrary(module);
		return TRUE;
	} else
		return FreeLibrary(module);
}

FARPROC MyGetProcAddress(HMODULE module, LPCSTR procname)
{
	FARPROC proc;
	LIST *lib = _FindMemoryModule(NULL, module);
	if (lib) {
		dprintf("MyGetProcAddress(%p, %p(%s))\n", module, procname, HIWORD(procname) ? procname : "");
		PUSH();
		proc = MemoryGetProcAddress(lib->module, procname);
		POP();
		dprintf("MyGetProcAddress(%p, %p(%s)) -> %p\n", module, procname, HIWORD(procname) ? procname : "", proc);
		return proc;
	} else
		return GetProcAddress(module, procname);
}
