#include "MemoryModule.h"
#include "MyLoadLibrary.h"

#include <string.h>
#include <malloc.h>
#include "uthash.h"

#include "debug.h"

typedef struct {
    PSTR name;
    PSTR fileName;

    HMODULE hAlias;
    PSTR *pAllowedPrefixes;
    PSTR *pAllowedSymbols;

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

BOOL SetAliasedModule(
    HMODULE hCustomModule, HMODULE hAliasedModule,
    const PSTR* ppAllowedPrefixes, const PSTR* ppAllowedSymbols)
{
    PHCUSTOMLIBRARY lib = _FindMemoryModule(NULL, hCustomModule);
    if (!lib)
        return FALSE;

    if (hAliasedModule)
        lib->hAlias = hAliasedModule;

    if (ppAllowedPrefixes)
        lib->pAllowedPrefixes = ppAllowedPrefixes;

    if (ppAllowedSymbols)
        lib->pAllowedSymbols = ppAllowedSymbols;

    return TRUE;
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
    hmodule->hAlias = NULL;
    hmodule->pAllowedPrefixes = NULL;
    hmodule->pAllowedSymbols = NULL;

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
    return MyLoadLibraryEx(name, bytes, dllmainArg, FALSE);
}

BOOL _CreateModuleMapping(HMODULE hModule, HANDLE *phMapping, PVOID *ppvMem)
{
    CHAR szDllPath[MAX_PATH+1];

    HANDLE hFile;
    HANDLE hMapping;
    PVOID pvMem;

    if (!GetModuleFileNameA(hModule, szDllPath, sizeof(szDllPath))) {
        return FALSE;
    }

    dprint("CreateMapping of %s\n", szDllPath);
    hFile = CreateFileA(
        szDllPath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        dprint("Failed to open %s: %d\n", szDllPath, GetLastError());
        return FALSE;
    }

    hMapping = CreateFileMappingA(
        hFile,
        NULL,
        PAGE_READONLY,
        0,
        0,
        NULL
    );

    CloseHandle(hFile);

    if (hMapping == INVALID_HANDLE_VALUE) {
        dprint("Failed create mapping of %s: %d\n", szDllPath, GetLastError());
        return FALSE;
    }

    pvMem = MapViewOfFile(
        hMapping,
        FILE_MAP_READ,
        0,
        0,
        0
    );

    if (!pvMem) {
        dprint("Failed create view of %s: %d\n", szDllPath, GetLastError());
        CloseHandle(hMapping);
        return FALSE;
    }

    *phMapping = hMapping;
    *ppvMem = pvMem;
    return TRUE;
}

HMODULE MyLoadLibraryEx(LPCSTR name, void *bytes, void *dllmainArg, BOOL blPrivate)
{
    HMODULE hLoadedModule = NULL;

    dprint("MyLoadLibrary '%s'..\n", name);
    if (blPrivate) {
        PHCUSTOMLIBRARY lib;
        lib = _FindMemoryModule(name, NULL);
        if (lib)
            return lib->module;
    } else {
        hLoadedModule = MyGetModuleHandleA(name);
    }

    dprint("MyLoadLibrary %s registered? %p\n", name, hLoadedModule);

    if (hLoadedModule)
        return hLoadedModule;

    if (bytes && !blPrivate) {
        HCUSTOMMODULE mod;
        PDL_CALLBACKS cb = libraries ? libraries->pCallbacks : &callbacks;

        dprint("Callbacks: %p\n", cb);

        mod = MemoryLoadLibraryEx(bytes, cb, dllmainArg, TRUE);

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

    if (bytes && blPrivate) {
        // Load private copy of system library
        HMODULE hAliased = (HMODULE) bytes;
        PVOID pvMem = NULL;
        HANDLE hMapping;

        if (_CreateModuleMapping(hAliased, &hMapping, &pvMem)) {
            HCUSTOMMODULE mod = NULL;
            PHCUSTOMLIBRARY lib = NULL;
            PDL_CALLBACKS cb = libraries ? libraries->pCallbacks : &callbacks;

            mod = MemoryLoadLibraryEx(pvMem, cb, NULL, FALSE);
            if (mod) {
                dprint("Loaded private %s aliased by %p\n", name, hAliased);
                lib = _AddMemoryModule(name, mod);
                lib->hAlias = hAliased;
            }

            UnmapViewOfFile(pvMem);
            CloseHandle(hMapping);

            if (lib)
                return lib->module;
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

BOOL isAllowedSymbol(PHCUSTOMLIBRARY lib, LPCSTR procname) {
    size_t proclen;

    if (HIWORD(procname) == 0) {
        return TRUE;
    }

    if (!lib->hAlias) {
        return TRUE;
    }

    if (!lib->pAllowedPrefixes && !lib->pAllowedSymbols) {
        return TRUE;
    }

    proclen = strlen(procname);

    if (lib->pAllowedPrefixes) {
        const PSTR *pIter;
        for (pIter=lib->pAllowedPrefixes; pIter && *pIter; pIter++) {
            LPCSTR pPrefix = *pIter;
            size_t len = strlen(pPrefix);

            if (len > proclen)
                continue;

            if (!strncmp(pPrefix, procname, len)) {
                dprint("Allow import %s@%s - prefix '%s' (%d)\n",
                    procname, lib->name, pPrefix, len);
                return TRUE;
            }
        }
    }

    if (lib->pAllowedSymbols) {
        const PSTR *pIter;
        for (pIter=lib->pAllowedSymbols; pIter && *pIter; pIter++) {
            LPCSTR pSymbol = *pIter;
            if (!strcmp(pSymbol, procname)) {
                dprint("Allow import %s@%s - by symbol\n");
                return TRUE;
            }
        }
    }

    dprint("Deny import: %s@%s (aliased: %p)\n",
        procname, lib->name, lib->hAlias);
    return FALSE;
}

FARPROC MyGetProcAddress(HMODULE module, LPCSTR procname)
{
    PHCUSTOMLIBRARY lib;
    FARPROC fpFunc = NULL;

    lib = _FindMemoryModule(NULL, module);
    if (lib) {
        if (isAllowedSymbol(lib, procname))
            fpFunc = MemoryGetProcAddress(lib->module, procname);
        if (!fpFunc && lib->hAlias) {
            fpFunc = GetProcAddress(lib->hAlias, procname);
        }
    } else {
        fpFunc = GetProcAddress(module, procname);
    }

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
