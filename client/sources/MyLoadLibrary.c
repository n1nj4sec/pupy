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

    if (!name && !module)
        return NULL;

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

        HASH_FIND(
            by_module, libraries->by_module,
            &module, sizeof(void *), phIdx
        );

        dprint("_FindMemoryModule by module %p -> %p (%p)\n", module, phIdx, phIdx? phIdx->module : NULL);
    }

    ReleaseSRWLockShared(&libraries->lock);

    return phIdx;
}

static PHCUSTOMLIBRARY _FindMemoryModuleW(LPCWSTR name)
{
    PSTR pszName = NULL;
    PHCUSTOMLIBRARY hResult = NULL;
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
        hResult = _FindMemoryModule(pszName, NULL);

    LocalFree(pszName);

    return hResult;
}

#ifdef _PUPY_PRIVATE_WS2_32
static
NTSTATUS CALLBACK MyEtwRegister (
    LPCGUID            ProviderId,
    PVOID               EnableCallback,
    PVOID              CallbackContext,
    PULONGLONG         RegHandle
) {
    static ULONGLONG dwFakeRegHandle = 0x80000000;
    dprint(
        "MyEtwRegister "
        "GUID=%08x-%04x-%04x-%02x%02x%02x%02x%02x%02x%02x%02x -> %p\n",
        ProviderId->Data1, ProviderId->Data2, ProviderId->Data3,
        ProviderId->Data4[0], ProviderId->Data4[1],
        ProviderId->Data4[2], ProviderId->Data4[3],
        ProviderId->Data4[4], ProviderId->Data4[5],
        ProviderId->Data4[6], ProviderId->Data4[7],
        dwFakeRegHandle
    );

    *RegHandle = dwFakeRegHandle ++;
    return ERROR_SUCCESS;
}

static
ULONG CALLBACK MyEtwEventWrite (
    ULONGLONG RegHandle,
    PVOID EventDescriptor,
    ULONG UserDataCount,
    PVOID UserData
) {
    dprint("MyEtwEventWrite (RegHandle: %p)\n", RegHandle);
    return ERROR_SUCCESS;
}

static
ULONG CALLBACK MyEtwEventWriteFull (
    ULONGLONG RegHandle,
    PVOID EventDescriptor,
    USHORT EventProperty,
    LPCGUID ActivityId,
    LPCGUID RelatedActivityId,
    ULONG UserDataCount,
    PVOID UserData
) {
    dprint("EtwEventWriteFull (RegHandle: %p)\n", RegHandle);
    return ERROR_SUCCESS;
}

static
NTSTATUS CALLBACK MyEtwUnregister (
    ULONGLONG RegHandle
) {
    dprint("MyEtwUnregister (RegHandle: %p)\n", RegHandle);
    return ERROR_SUCCESS;
}
#endif

static DL_CALLBACKS callbacks = {
    MyLoadLibraryA, MyLoadLibraryW,
    MyLoadLibraryExA, MyLoadLibraryExW,
    MyGetModuleHandleA, MyGetModuleHandleW,
    MyGetModuleFileNameA, MyGetModuleFileNameW,
    MyGetProcAddress,
    MyFreeLibrary,

    MyFindResourceA, MyFindResourceW,
    MyFindResourceExA, MyFindResourceExW,
    MySizeofResource, MyLoadResource,

    GetProcAddress,
    GetModuleFileNameA, GetModuleFileNameW,
    FindResourceExW, SizeofResource, LoadResource,

#ifdef _PUPY_PRIVATE_WS2_32
    MyEtwRegister, MyEtwEventWrite,
    MyEtwEventWriteFull, MyEtwUnregister
#endif
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

DWORD CALLBACK MyGetModuleFileNameW(HMODULE hModule, LPWSTR lpwStr, DWORD dwSize)
{
    PHCUSTOMLIBRARY lib;

    lib = _FindMemoryModule(NULL, hModule);
    if (lib) {
        DWORD dwRet = MemoryModuleFileNameW(lib->module, lpwStr, dwSize);
        if (dwRet == 0xFFFFFFFF) {
            dwRet = MultiByteToWideChar(
                CP_ACP, 0,
                lib->fileName, strlen(lib->fileName),
                lpwStr, dwSize
            );

            dprint(
                "MyGetModuleFileNameW -> %s (conv: %d)\n",
                lib->fileName, dwRet
            );
        } else {
            dprint(
                "MyGetModuleFileNameW -> proxied (ret: %d)\n", dwRet
            );
        }

        return dwRet;
    } else {
        dprint("MyGetModuleFileNameW %p -> unregistered\n", hModule);
    }

    return GetModuleFileNameW(hModule, lpwStr, dwSize);
}

DWORD CALLBACK MyGetModuleFileNameA(HMODULE hModule, LPSTR lpStr, DWORD dwSize)
{
    PHCUSTOMLIBRARY lib;

    lib = _FindMemoryModule(NULL, hModule);
    if (lib) {
        DWORD dwRet = MemoryModuleFileNameA(lib->module, lpStr, dwSize);
        if (dwRet == 0xFFFFFFFF) {
            size_t reqSize = strlen(lib->fileName);
            if (reqSize < dwSize) {
                SetLastError(ERROR_INSUFFICIENT_BUFFER);
                dwRet = 0;
            } else {
                memcpy(lpStr, lib->fileName, reqSize);
                if (dwSize+1 == reqSize) {
                    lpStr[reqSize] = '\0';
                }
                dwRet = reqSize;
            }

            dprint(
                "MyGetModuleFileNameA -> %s (conv: %d)\n",
                lib->fileName, dwRet
            );
        } else {
            dprint(
                "MyGetModuleFileNameA -> proxied (ret: %s/%d)\n", lpStr, dwRet
            );
        }
        return dwRet;
    } else {
        dprint("MyGetModuleFileNameA %p -> unregistered\n", hModule);
    }

    return GetModuleFileNameA(hModule, lpStr, dwSize);
}


HMODULE CALLBACK MyGetModuleHandleA(LPCSTR name)
{
    PHCUSTOMLIBRARY lib;

    lib = _FindMemoryModule(name, NULL);
    if (lib)
        return lib->module;

    return GetModuleHandleA(name);
}

HMODULE MyLoadLibrary(LPCSTR name, void *bytes, void *dllmainArg)
{
    return MyLoadLibraryEx(
        name, bytes, dllmainArg, NULL, MEMORY_LOAD_DEFAULT
    );
}

HMODULE
MyLoadLibraryEx(
    LPCSTR name, const void *bytes, void *dllmainArg,
    const void *pvExports, MEMORY_LOAD_FLAGS flags)
{
    HMODULE hLoadedModule = NULL;

    dprint("MyLoadLibrary '%s'..\n", name);
    if (flags & MEMORY_LOAD_FROM_HMODULE) {
        PHCUSTOMLIBRARY lib;
        lib = _FindMemoryModule(name, NULL);
        if (lib)  {
            lib->refcount ++;
            return lib->module;
        }
    } else {
        hLoadedModule = MyGetModuleHandleA(name);
    }

    dprint("MyLoadLibrary %s registered? %p\n", name, hLoadedModule);

    if (hLoadedModule)
        return hLoadedModule;

    if (bytes) {
        HCUSTOMMODULE mod;
        PDL_CALLBACKS cb = libraries ? libraries->pCallbacks : &callbacks;

        dprint("Callbacks: %p\n", cb);

        mod = MemoryLoadLibraryEx(bytes, cb, dllmainArg, pvExports, flags);

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

HMODULE CALLBACK MyGetModuleHandleW(LPCWSTR name) {
    PHCUSTOMLIBRARY hResult = _FindMemoryModuleW(name);
    if (hResult)
        return hResult;

    return GetModuleHandleW(name);
}

HMODULE CALLBACK MyLoadLibraryExA(LPCSTR name, HANDLE hFile, DWORD dwFlags) {
    PHCUSTOMLIBRARY hResult = _FindMemoryModule(name, NULL);
    if (hResult) {
        hResult->refcount ++;
        return hResult->module;
    }

    return LoadLibraryExA(name, hFile, dwFlags);
}

HMODULE CALLBACK MyLoadLibraryExW(LPCWSTR name, HANDLE hFile, DWORD dwFlags) {
    PHCUSTOMLIBRARY hResult = _FindMemoryModuleW(name);
    if (hResult) {
        hResult->refcount ++;
        return hResult->module;
    }

    return LoadLibraryExW(name, hFile, dwFlags);
}

HMODULE CALLBACK MyLoadLibraryA(LPCSTR name) {
    PHCUSTOMLIBRARY hResult = _FindMemoryModule(name, NULL);
    if (hResult) {
        hResult->refcount ++;
        return hResult->module;
    }

    return LoadLibraryA(name);
}

HMODULE CALLBACK MyLoadLibraryW(LPCWSTR name) {
    PHCUSTOMLIBRARY hResult = _FindMemoryModuleW(name);
    if (hResult) {
        hResult->refcount ++;
        return hResult->module;
    }

    return LoadLibraryW(name);
}

BOOL CALLBACK MyFreeLibrary(HMODULE module)
{
    PHCUSTOMLIBRARY lib = _FindMemoryModule(NULL, module);

    if (lib) {
        dprint("MyFreeLibrary(%p) -> %s REFCNT: %d\n",
            module, lib->name, lib->refcount);

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

FARPROC CALLBACK MyGetProcAddress(HMODULE module, LPCSTR procname)
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
            module, LOWORD(procname), fpFunc, lib);
    } else {
        dprint("MyGetProcAddress(%p, %s) -> %p (lib: %p)\n", module, procname, fpFunc, lib);
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

HRSRC CALLBACK MyFindResourceA(HMODULE module, LPCSTR name, LPCSTR type)
{
    HRSRC res;
    PHCUSTOMLIBRARY lib;

    lib = _FindMemoryModule(NULL, module);
    if (lib)
        res = (HRSRC) MemoryFindResourceA(lib->module, name, type);
    else
        res = FindResourceA(module, name, type);

    dprint("MyFindResourceA(%p, %s, %s) -> %p (%p)\n", module, name, type, res, lib);
    return res;
}

HRSRC CALLBACK MyFindResourceW(HMODULE module, LPCWSTR name, LPCWSTR type)
{
    HRSRC res;
    PHCUSTOMLIBRARY lib;

    lib = _FindMemoryModule(NULL, module);
    if (lib)
        res = (HRSRC) MemoryFindResourceW(lib->module, name, type);
    else
        res = FindResourceW(module, name, type);

    dprint("MyFindResourceA(%p, %p, %p) -> %p (%p)\n", module, name, type, res, lib);
    return res;
}

HRSRC CALLBACK MyFindResourceExA(HMODULE hModule, LPCSTR name, LPCSTR type, WORD language)
{
    HRSRC res;
    PHCUSTOMLIBRARY lib;

    lib = _FindMemoryModule(NULL, hModule);
    if (lib)
        res = (HRSRC) MemoryFindResourceExA(lib->module, name, type, language);
    else
        res = FindResourceExA(hModule, name, type, language);

    dprint("MyFindResourceExA(%p, %s, %s, %d) -> %p (%p)\n", hModule, name, type, language, res, lib);
    return res;
}

HRSRC CALLBACK MyFindResourceExW(HMODULE hModule, LPCWSTR name, LPCWSTR type, WORD language)
{
    HRSRC res;
    PHCUSTOMLIBRARY lib;

    lib = _FindMemoryModule(NULL, hModule);
    if (lib)
        res = (HRSRC) MemoryFindResourceExW(lib->module, name, type, language);
    else
        res = FindResourceExW(hModule, name, type, language);

    dprint("MyFindResourceExA(%p, %p, %p, %d) -> %p (%p)\n", hModule, name, type, language, res, lib);
    return res;
}

DWORD CALLBACK MySizeofResource(HMODULE hModule, HRSRC resource)
{
    PHCUSTOMLIBRARY lib;
    DWORD res;

    lib = _FindMemoryModule(NULL, hModule);
    if (lib)
        res = MemorySizeofResource(lib->module, (HMEMORYRSRC) resource);
    else
        res = SizeofResource(hModule, resource);

    dprint("MySizeofResource(%p, %p) -> %d (%p)\n", hModule, resource, res, lib);
    return res;
}

LPVOID CALLBACK MyLoadResource(HMODULE hModule, HRSRC resource)
{
    PHCUSTOMLIBRARY lib;
    LPVOID res;

    lib = _FindMemoryModule(NULL, hModule);
    if (lib)
        res = MemoryLoadResource(lib->module, (HMEMORYRSRC) resource);
    else
        res = LoadResource(hModule, resource);

    dprint("MyLoadResource(%p, %p) -> %d (%p)\n", hModule, resource, res, lib);
    return res;
}
