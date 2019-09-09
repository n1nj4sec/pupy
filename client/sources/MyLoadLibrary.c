#include "MemoryModule.h"
#include "MyLoadLibrary.h"

#include <string.h>
#include <malloc.h>
#include "uthash.h"

#include "debug.h"

typedef struct {
    PSTR name;
    HCUSTOMMODULE module;
    int refcount;

    UT_hash_handle by_name;
    UT_hash_handle by_module;
} HCUSTOMLIBRARY, *PHCUSTOMLIBRARY;

typedef struct {
    PHCUSTOMLIBRARY by_module;
    PHCUSTOMLIBRARY by_name;
    SRWLOCK lock;
} HLIBRARIES, *PHLIBRARIES;

static PHLIBRARIES libraries = NULL;

VOID MySetLibraries(PVOID pLibraries) {
    if (!libraries) {
        dprint("Initialize libraries with: %p\n", pLibraries);
        libraries = pLibraries;
    } else {
        dprint("Libraries already initialized\n");
    }
}

PVOID MyGetLibraries() {
    return (PVOID) libraries;
}

/****************************************************************
 * Search for a loaded MemoryModule in the linked list, either by name
 * or by module handle.
 */
static PHCUSTOMLIBRARY _FindMemoryModule(LPCSTR name, HMODULE module)
{
    PHCUSTOMLIBRARY phIdx = NULL;

    if (!libraries)
        return NULL;

    AcquireSRWLockShared(&libraries->lock);

    if (name) {
        PSTR srcName = NULL;
        PSTR psName;
        size_t len;

        srcName = strrchr(name, '\\');

        if (!srcName)
            srcName = strrchr(name, '/');

        if (!srcName)
            srcName = name;

        len = strlen(srcName);
        psName = _alloca(len + 1);
        memcpy(psName, srcName, len+1);
        _strupr(psName);

        dprint(
            "_FindMemoryModule by name %s %d (%s).. \n",
            srcName, len, psName);

        HASH_FIND(
            by_name, libraries->by_name,
            psName, len, phIdx
        );

        dprint(
            "_FindMemoryModule by name %s -> %p (%p)\n",
            psName, phIdx, phIdx? phIdx->module : NULL);
    } else {
        dprint("_FindMemoryModule by module %p.. \n", module);

        HASH_FIND(
            by_module, libraries->by_module,
            &module, sizeof(void *), phIdx
        );

        dprint("_FindMemoryModule by module %p -> %p (%p)\n", module, phIdx, phIdx? phIdx->module : NULL);
    }

    ReleaseSRWLockShared(&libraries->lock);

    return phIdx;
}

/****************************************************************
 * Insert a MemoryModule into the linked list of loaded modules
 */
static PHCUSTOMLIBRARY _AddMemoryModule(
    LPCSTR name, HCUSTOMMODULE module)
{
    PHCUSTOMLIBRARY hmodule = (PHCUSTOMLIBRARY) malloc(
        sizeof(HCUSTOMLIBRARY));

    PSTR srcName = NULL;

    if (!libraries) {
        libraries = (PHLIBRARIES) malloc(sizeof(HLIBRARIES));
        libraries->by_module = NULL;
        libraries->by_name = NULL;
        InitializeSRWLock(&libraries->lock);
        dprint("Initialize libraries: %p\n", libraries);
    }

    srcName = strrchr(name, '\\');

    if (!srcName)
        srcName = strrchr(name, '/');

    if (!srcName)
        srcName = name;

    hmodule->refcount = 1;
    hmodule->name = strdup(srcName);
    hmodule->module = module;

    _strupr(hmodule->name);

    AcquireSRWLockExclusive(&libraries->lock);

    dprint(
        "_AddMemoryModule(%s, %p (s=%d)) .. #1\n",
        hmodule->name, module, sizeof(hmodule->module));

    HASH_ADD_KEYPTR(
        by_module, libraries->by_module,
        &hmodule->module, sizeof(hmodule->module),
        hmodule
    );

    dprint("_AddMemoryModule(%s, %p) .. #2\n", hmodule->name, module);

    HASH_ADD_KEYPTR(
        by_name, libraries->by_name, hmodule->name,
        strlen(hmodule->name), hmodule
    );

    dprint("_AddMemoryModule(%s, %p) .. #3\n", 
        hmodule->name, module);

    ReleaseSRWLockExclusive(&libraries->lock);

    dprint("_AddMemoryModule(%s, %p) -> %p[%d] (hmod=%p)\n",
        hmodule->name, module, hmodule, hmodule->refcount, module);

    return hmodule;
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
    PHCUSTOMLIBRARY lib;

    lib = _FindMemoryModule(filename, NULL);
    if (lib) {
        lib->refcount += 1;

        printf("_LoadLibrary(%s, %p) -> %s[%d]\n\n",
            filename, userdata, lib->name, lib->refcount);
        return lib->module;
    } else {
        dprint(
            "_LoadLibrary(%s, %p): _FindMemoryModule failed\n",
            filename, userdata
        );
    }

    result = (HCUSTOMMODULE) LoadLibraryA(filename);

    dprint("LoadLibraryA(%s) -> %p\n\n", filename, result);
    return result;
}

/****************************************************************
 * Public functions
 */
HMODULE MyGetModuleHandle(LPCSTR name)
{
    PHCUSTOMLIBRARY lib;
    lib = _FindMemoryModule(name, NULL);
    if (lib)
        return lib->module;
    return GetModuleHandle(name);
}

HMODULE MyLoadLibrary(LPCSTR name, void *bytes, void *dllmainArg)
{
    if (bytes) {
        HCUSTOMMODULE mod = MemoryLoadLibraryEx(bytes,
                            _LoadLibrary,
                            _GetProcAddress,
                            _FreeLibrary,
                            NULL, dllmainArg);

        dprint(
            "MyLoadLibrary: loading %s, buf=%p (dllmainArg=%p) -> %p\n",
            name, bytes, dllmainArg, mod
        );

        if (mod) {
            PHCUSTOMLIBRARY lib = _AddMemoryModule(name, mod);
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
    PHCUSTOMLIBRARY lib = _FindMemoryModule(NULL, module);
    if (lib) {
        if (--lib->refcount == 0) {
            AcquireSRWLockExclusive(&libraries->lock);

            HASH_DELETE(by_name, libraries->by_name, lib);
            HASH_DELETE(by_module, libraries->by_module, lib);

            ReleaseSRWLockExclusive(&libraries->lock);

            free(lib->name);
            free(lib);

            MemoryFreeLibrary(module);
        }
        return TRUE;
    } else
        return FreeLibrary(module);
}

FARPROC MyGetProcAddress(HMODULE module, LPCSTR procname)
{
    FARPROC proc;
    PHCUSTOMLIBRARY lib = _FindMemoryModule(NULL, module);
    if (lib) {
        /* dprint("MyGetProcAddress(%p, %p(%s))\n", module, procname, HIWORD(procname) ? procname : ""); */

        proc = MemoryGetProcAddress(lib->module, procname);

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
