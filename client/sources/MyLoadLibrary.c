#include "Python-dynload.h"
#include "debug.h"
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
            /* dprint("_FindMemoryModule(%s, %p) -> %s[%d]\n", name, module, lib->name, lib->refcount); */
            return lib;
        } else if (module == lib->module) {
            /* dprint("_FindMemoryModule(%s, %p) -> %s[%d]\n", name, module, lib->name, lib->refcount); */
            return lib;
        } else {
            lib = lib->next;
        }
    }
    /* dprint("_FindMemoryModule(%s, %p) -> NONE\n", name, module); */
    return NULL;
}

/****************************************************************
 * Insert a MemoryModule into the linked list of loaded modules
 */
static LIST *_AddMemoryModule(LPCSTR name, HCUSTOMMODULE module)
{
    LIST *entry = (LIST *) malloc(sizeof(LIST));
    entry->name = _strdup(name);
    entry->module = module;
    entry->next = libraries;
    entry->prev = NULL;
    entry->refcount = 1;
    libraries = entry;

    dprint("_AddMemoryModule(%s, %p) -> %p[%d]\n",
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

    PUSH();
    lib = _FindMemoryModule(filename, NULL);
    if (lib) {
        lib->refcount += 1;
        POP();
        printf("_LoadLibrary(%s, %p) -> %s[%d]\n\n",
            filename, userdata, lib->name, lib->refcount);
        return lib->module;
    } else {
        dprint(
            "_LoadLibrary(%s, %p): _FindMemoryModule failed\n",
            filename, userdata
        );
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
                dprint("_LoadLibrary(%s, %p) -> %s[%d]\n\n",
                    filename, userdata, lib->name, lib->refcount);
                return lib->module;
            } else {
                dprint("_LoadLibrary(%s, %p) failed with error %d\n",
                    filename, userdata, GetLastError());
            }
        } else {
            PyErr_Clear();
        }
    }
    result = (HCUSTOMMODULE) LoadLibraryA(filename);
    POP();
    dprint("LoadLibraryA(%s) -> %p\n\n", filename, result);
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
    dprint("MyLoadLibrary: loading %s (userdata=%p)\n", name, userdata);

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
            dprint("MemoryLoadLibraryEx: loaded %s -> %p (%p)\n", name, mod, lib->module);
            return lib->module;
        } else {
            dprint("MemoryLoadLibraryEx(%s, %p) failed\n", name, bytes);
        }
    }

    dprint("MyLoadLibrary: fallback to OS LoadLibrary %s\n", name);
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
        /* dprint("MyGetProcAddress(%p, %p(%s))\n", module, procname, HIWORD(procname) ? procname : ""); */
        PUSH();
        proc = MemoryGetProcAddress(lib->module, procname);
        POP();
        /* dprint("MyGetProcAddress(%p, %p(%s)) -> %p\n", module, procname, HIWORD(procname) ? procname : "", proc); */
        return proc;
    } else
        return GetProcAddress(module, procname);
}

FARPROC MyFindProcAddress(LPCSTR modulename, LPCSTR procname)
{
    HCUSTOMMODULE mod = MyGetModuleHandle(modulename);
    void *addr = NULL;
    /* dprint("MyFindProcAddress(%s, %s) -> %p\n", modulename, procname, mod); */
    if (mod) {
        addr = MyGetProcAddress(mod, procname);
    }

    /* dprint("MyFindProcAddress(%s, %s) -> %p\n", modulename, procname, addr); */
    return addr;
}
