#include "MemoryModule.h"
#include "MyLoadLibrary.h"

#include <string.h>
#include <malloc.h>
#include "uthash.h"

#include "debug.h"

typedef struct {
    PSTR name;
    PSTR fileName;

    HCUSTOMMODULE module;
    int refcount;

    UT_hash_handle by_name;
    UT_hash_handle by_filename;
    UT_hash_handle by_module;
} HCUSTOMLIBRARY, *PHCUSTOMLIBRARY;

typedef struct {
    PHCUSTOMLIBRARY by_module;
    PHCUSTOMLIBRARY by_name;
    PHCUSTOMLIBRARY by_filename;
    SRWLOCK lock;
    PDL_CALLBACKS pCallbacks;
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
        LPCSTR srcName = NULL;
        PSTR psName;
        PSTR psFileName;
        PSTR psi;
        size_t len, fileNameLen;

        srcName = strrchr(name, '\\');
        if (srcName)
            srcName ++;

        if (!srcName || !srcName[0]) {
            srcName = strrchr(name, '/');
            if (srcName)
                srcName ++;
        }

        if (!srcName || !srcName[0])
            srcName = name;

        len = strlen(srcName);
        fileNameLen = strlen(name);

        psName = _alloca(len + 1);
        psFileName = _alloca(fileNameLen + 1);
        memcpy(psName, srcName, len+1);
        memcpy(psFileName, name, len+1);

        _strupr(psName);
        _strupr(psFileName);

        psi = strrchr(psName, '.');
        if (psi && !strcmp(psi, ".DLL"))
            *psi = '\0';

        for (psi=psFileName; *psi; psi++)
            if (*psi == '/')
                *psi = '\\';

        dprint(
            "_FindMemoryModule by name %s %d (%s).. \n",
            srcName, len, psName);

        HASH_FIND(
            by_filename, libraries->by_filename,
            psFileName, fileNameLen, phIdx
        );

        if (!phIdx) {
            HASH_FIND(
                by_name, libraries->by_name,
                psName, len, phIdx
            );
        }

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

static DL_CALLBACKS callbacks = {
    MyLoadLibraryA, MyLoadLibraryW,
    MyLoadLibraryExA, MyLoadLibraryExW,
    MyGetModuleHandleA, MyGetModuleHandleW,
    MyGetProcAddress,
    MyFreeLibrary
};

/****************************************************************
 * Insert a MemoryModule into the linked list of loaded modules
 */
static PHCUSTOMLIBRARY _AddMemoryModule(
    LPCSTR name, HCUSTOMMODULE module)
{
    PHCUSTOMLIBRARY hmodule = (PHCUSTOMLIBRARY) malloc(
        sizeof(HCUSTOMLIBRARY));

    LPCSTR srcName = NULL;
    PSTR psi;

    if (!libraries) {
        libraries = (PHLIBRARIES) malloc(sizeof(HLIBRARIES));
        libraries->by_module = NULL;
        libraries->by_name = NULL;
        libraries->by_filename = NULL;
        libraries->pCallbacks = &callbacks;

        InitializeSRWLock(&libraries->lock);
        dprint("Initialize libraries: %p\n", libraries);
    }

    srcName = strrchr(name, '\\');
    if (srcName)
        srcName ++;

    if (!srcName || !srcName[0]) {
        srcName = strrchr(name, '/');
        if (srcName)
            srcName ++;
    }

    if (!srcName || !srcName[0])
        srcName = name;

    hmodule->refcount = 1;
    hmodule->name = strdup(srcName);
    hmodule->fileName = strdup(name);
    hmodule->module = module;

    _strupr(hmodule->name);
    _strupr(hmodule->fileName);

    psi = strchr(hmodule->name, '.');
    if (psi && !strcmp(psi, ".DLL"))
        *psi = '\0';

    for (psi=hmodule->fileName; *psi; psi++)
        if (*psi == '/')
            *psi = '\\';

    AcquireSRWLockExclusive(&libraries->lock);

    HASH_ADD_KEYPTR(
        by_module, libraries->by_module,
        &hmodule->module, sizeof(hmodule->module),
        hmodule
    );

    dprint(
        "_AddMemoryModule(%s (%s), %p)\n",
        hmodule->name,
        hmodule->fileName,
        module
    );

    HASH_ADD_KEYPTR(
        by_name, libraries->by_name, hmodule->name,
        strlen(hmodule->name), hmodule
    );

    HASH_ADD_KEYPTR(
        by_filename, libraries->by_filename, hmodule->fileName,
        strlen(hmodule->fileName), hmodule
    );

    ReleaseSRWLockExclusive(&libraries->lock);

    dprint("_AddMemoryModule(%s, %p) -> %p[%d] (hmod=%p)\n",
        hmodule->name, module, hmodule, hmodule->refcount, module);

    return hmodule;
}

/****************************************************************
 * Public functions
 */
HMODULE MyGetModuleHandleA(LPCSTR name)
{
    PHCUSTOMLIBRARY lib;

    lib = _FindMemoryModule(name, NULL);
    if (lib)
        return lib->module;

    return GetModuleHandleA(name);
}

HMODULE MyLoadLibrary(LPCSTR name, void *bytes, void *dllmainArg)
{
    HMODULE hLoadedModule;

    dprint("MyLoadLibrary '%s'..\n", name);
    hLoadedModule = MyGetModuleHandleA(name);

    dprint("MyLoadLibrary %s registered? %p\n", name, hLoadedModule);

    if (hLoadedModule)
        return hLoadedModule;

    if (bytes) {
        HCUSTOMMODULE mod;
        PDL_CALLBACKS cb = libraries ? libraries->pCallbacks : &callbacks;

        dprint("Callbacks: %p\n", cb);

        mod = MemoryLoadLibraryEx(bytes, cb, dllmainArg);

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

HMODULE MyGetModuleHandleW(LPCWSTR name) {
    PSTR pszName = NULL;
    HMODULE hResult = NULL;
    DWORD dwRequiredSize = WideCharToMultiByte(
        CP_OEMCP, 0, name, -1, NULL,
        0, NULL, NULL
    );

    if (!SUCCEEDED(dwRequiredSize))
        return NULL;

    dwRequiredSize += 1;

    pszName = LocalAlloc(LMEM_FIXED, dwRequiredSize);
    if (!pszName)
        return NULL;

    dwRequiredSize = WideCharToMultiByte(
        CP_OEMCP, 0, name, -1, pszName,
        dwRequiredSize, NULL, NULL
    );

    if (SUCCEEDED(dwRequiredSize))
        hResult = MyGetModuleHandleA(pszName);

    LocalFree(pszName);

    if (hResult)
        return hResult;

    return GetModuleHandleW(name);
}

HMODULE MyLoadLibraryExA(LPCSTR name, HANDLE hFile, DWORD dwFlags) {
    HMODULE hModule = MyGetModuleHandleA(name);
    if (hModule)
        return hModule;

    return LoadLibraryExA(name, hFile, dwFlags);
}

HMODULE MyLoadLibraryExW(LPCWSTR name, HANDLE hFile, DWORD dwFlags) {
    HMODULE hModule = MyGetModuleHandleW(name);
    if (hModule)
        return hModule;

    return LoadLibraryExW(name, hFile, dwFlags);
}

HMODULE MyLoadLibraryA(LPCSTR name) {
    HMODULE hModule = MyGetModuleHandleA(name);
    if (hModule)
        return hModule;

    return LoadLibraryA(name);
}

HMODULE MyLoadLibraryW(LPCWSTR name) {
    HMODULE hModule = MyGetModuleHandleW(name);
    if (hModule)
        return hModule;

    return LoadLibraryW(name);
}

BOOL MyFreeLibrary(HMODULE module)
{
    PHCUSTOMLIBRARY lib = _FindMemoryModule(NULL, module);
    if (lib) {
        if (--lib->refcount == 0) {
            AcquireSRWLockExclusive(&libraries->lock);

            HASH_DELETE(by_name, libraries->by_name, lib);
            HASH_DELETE(by_filename, libraries->by_filename, lib);
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
    PHCUSTOMLIBRARY lib;
    FARPROC fpFunc = NULL;

    lib = _FindMemoryModule(NULL, module);
    if (lib)
        fpFunc = MemoryGetProcAddress(lib->module, procname);
    else
        fpFunc = GetProcAddress(module, procname);

    if (HIWORD(procname) == 0) {
        dprint("MyGetProcAddress(%p, %d) -> %p (lib: %p)\n",
            module, LOWORD(procname), lib);
    } else {
        dprint("MyGetProcAddress(%p, %s) -> %p (lib: %p)\n", module, procname, lib);
    }

    return fpFunc;
}

FARPROC MyFindProcAddress(LPCSTR modulename, LPCSTR procname)
{
    HCUSTOMMODULE mod = MyGetModuleHandleA(modulename);
    void *addr = NULL;
    /* dprint("MyFindProcAddress(%s, %s) -> %p\n", modulename, procname, mod); */
    if (mod) {
        addr = MyGetProcAddress(mod, procname);
    }

    /* dprint("MyFindProcAddress(%s, %s) -> %p\n", modulename, procname, addr); */
    return addr;
}
