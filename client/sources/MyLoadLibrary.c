#include "MemoryModule.h"
#include "MyLoadLibrary.h"

#include <string.h>
#include <malloc.h>
#include "uthash.h"

#include "debug.h"

typedef struct _ORIGINAL_THREAD_ARGS {
    LPTHREAD_START_ROUTINE lpOriginalRoutine;
    LPVOID lpOriginalParameter;
    LPTOP_LEVEL_EXCEPTION_FILTER lpExceptionFilter;
} ORIGINAL_THREAD_ARGS, *PORIGINAL_THREAD_ARGS;

typedef struct {
    PSTR name;
    PSTR fileName;

    LPTOP_LEVEL_EXCEPTION_FILTER ehFilter;

    HCUSTOMMODULE module;
    int refcount;
    int pin;

    UT_hash_handle by_name;
    UT_hash_handle by_filename;
    UT_hash_handle by_module;
} HCUSTOMLIBRARY, *PHCUSTOMLIBRARY;

typedef struct {
    PHCUSTOMLIBRARY by_module;
    PHCUSTOMLIBRARY by_name;
    PHCUSTOMLIBRARY by_filename;
    CRITICAL_SECTION lock;
    PDL_CALLBACKS pCallbacks;
} HLIBRARIES, *PHLIBRARIES;

static PHLIBRARIES libraries = NULL;
static LPTOP_LEVEL_EXCEPTION_FILTER lpDefaultExceptionHandler = NULL;

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

static PHCUSTOMLIBRARY _FindMemoryModuleByAddress(
        PVOID pvAddress, PVOID *ppvBaseAddress) {
    PHCUSTOMLIBRARY module, tmp;
    UINT_PTR uiAddress = (UINT_PTR) pvAddress;

    if (!pvAddress)
        return NULL;

    HASH_ITER(by_module, libraries->by_module, module, tmp) {
        PVOID pvBaseAddress = NULL;
        ULONG ulSize = 0;

        if (GetMemoryModuleInfo(module->module, &pvBaseAddress, &ulSize)) {
            UINT_PTR uiBaseAddress = (UINT_PTR) pvBaseAddress;

            if (uiAddress >= uiBaseAddress && uiAddress <= (uiBaseAddress + ulSize)) {
                if (ppvBaseAddress)
                    *ppvBaseAddress = pvBaseAddress;

                return module;
            }
        }
    }

    return NULL;
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

    EnterCriticalSection(&libraries->lock);

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

    LeaveCriticalSection(&libraries->lock);

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
    MyGetModuleHandleExA, MyGetModuleHandleExW,
    MyGetModuleFileNameA, MyGetModuleFileNameW,
    MyGetProcAddress,
    MyFreeLibrary,

    MyFindResourceA, MyFindResourceW,
    MyFindResourceExA, MyFindResourceExW,
    MySizeofResource, MyLoadResource,

    GetProcAddress,
    GetModuleFileNameA, GetModuleFileNameW,
    FindResourceExW, SizeofResource, LoadResource,

    MyCreateThread,

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

        InitializeCriticalSection(&libraries->lock);
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
    hmodule->pin = 0;
    hmodule->name = strdup(srcName);
    hmodule->fileName = strdup(name);
    hmodule->module = module;
    hmodule->ehFilter = NULL;

    _strupr(hmodule->name);
    _strupr(hmodule->fileName);

    psi = strchr(hmodule->name, '.');
    if (psi && !strcmp(psi, ".DLL"))
        *psi = '\0';

    for (psi=hmodule->fileName; *psi; psi++)
        if (*psi == '/')
            *psi = '\\';

    EnterCriticalSection(&libraries->lock);

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

    LeaveCriticalSection(&libraries->lock);

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
            if (reqSize > dwSize) {
                SetLastError(ERROR_INSUFFICIENT_BUFFER);
                dwRet = 0;
            } else {
                memcpy(lpStr, lib->fileName, reqSize);
                if (dwSize >= reqSize + 1) {
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

static
BOOL MyGetModuleHandleEx(DWORD dwFlags, LPVOID lpArg, HMODULE *phModule, BOOL bWide)
{
    PHCUSTOMLIBRARY lib;

    if (dwFlags & GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS) {
        dprint("MyGetModuleHandleEx -> by Address (%p)", lpArg);
        lib = _FindMemoryModuleByAddress(lpArg, NULL);
    } else {
        if (bWide) {
            dwprint(L"MyGetModuleHandleEx -> by Name (%s)", lpArg);
            lib = _FindMemoryModuleW(lpArg, NULL);
        } else {
            dprint("MyGetModuleHandleEx -> by Name (%s)", lpArg);
            lib = _FindMemoryModule(lpArg, NULL);
        }
    }

    if (!lib)  {
        dprint(" -> NULL\n", phModule);
        if (bWide) {
            return GetModuleHandleExW(dwFlags, lpArg, phModule);
        } else {
            return GetModuleHandleExA(dwFlags, lpArg, phModule);
        }
    }

    dprint(" -> Found (%p:%s)", lib->module, lib->name);

    if (dwFlags & GET_MODULE_HANDLE_EX_FLAG_PIN) {
        dprint(" -> set pin\n");
        lib->pin = 1;
    } else if (! (dwFlags & GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT)) {
        lib->refcount ++;
        dprint(" -> incr refcnt (%d)\n", lib->refcount);
    } else {
        dprint(" -> do nothing\n", lib->refcount);
    }

    if (phModule)
        *phModule = lib->module;

    return TRUE;
}

BOOL CALLBACK MyGetModuleHandleExA(DWORD dwFlags, LPVOID lpArg, HMODULE *phModule) {
    return MyGetModuleHandleEx(dwFlags, lpArg, phModule, FALSE);
}

BOOL CALLBACK MyGetModuleHandleExW(DWORD dwFlags, LPVOID lpArg, HMODULE *phModule) {
    return MyGetModuleHandleEx(dwFlags, lpArg, phModule, TRUE);
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
        return (HMODULE) hResult;

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
        dprint("MyFreeLibrary(%p) -> %s REFCNT: %d PIN: %d\n",
            module, lib->name, lib->refcount, lib->pin);

        if (lib->pin == 0 && --lib->refcount == 0) {
            EnterCriticalSection(&libraries->lock);

            HASH_DELETE(by_name, libraries->by_name, lib);
            HASH_DELETE(by_filename, libraries->by_filename, lib);
            HASH_DELETE(by_module, libraries->by_module, lib);

            LeaveCriticalSection(&libraries->lock);

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

BOOL MySetUnhandledExceptionFilter(LPCSTR pszModuleName, LPTOP_LEVEL_EXCEPTION_FILTER handler)
{
    PHCUSTOMLIBRARY lib;

    if (!pszModuleName) {
        lpDefaultExceptionHandler = handler;
        dprint("Set default thread handler to %p\n", lpDefaultExceptionHandler);
        return TRUE;
    }

    lib = _FindMemoryModule(pszModuleName, NULL);
    if (!lib) {
        dprint(
            "Failed to set default thread handler for %s to %p - module not found\n",
            pszModuleName, lpDefaultExceptionHandler
        );
    }

    lib->ehFilter = handler;

    dprint(
        "Set default thread handler for %s to %p\n",
        pszModuleName, lpDefaultExceptionHandler
    );

    return TRUE;
}

LPTOP_LEVEL_EXCEPTION_FILTER MyGetUnhandledExceptionFilter(VOID) {
    return lpDefaultExceptionHandler;
}

LONG WINAPI ThreadUnhandledExceptionFilter(
    DWORD dwExceptionCode, PEXCEPTION_POINTERS pExceptionPointers,
    PVOID pvThreadProc, LPTOP_LEVEL_EXCEPTION_FILTER lpFilter, LONG lResult
) {
    LPCSTR pszName = NULL;
    LPTOP_LEVEL_EXCEPTION_FILTER lpCustomFilter = NULL;

    LONG lVerdict = EXCEPTION_CONTINUE_SEARCH;

    if (dwExceptionCode == EXCEPTION_BREAKPOINT) {
        dprint(
            "ThreadUnhandledExceptionFilter (ThreadProc=%p): hit breakpoint (???) - ignore",
            pvThreadProc
        );

        return EXCEPTION_CONTINUE_SEARCH;
    }

    if (MyFindMemoryModuleNameByAddr(pvThreadProc, &pszName, NULL, &lpCustomFilter)) {
        dprint(
            "ThreadUnhandledExceptionFilter (ThreadProc=%p) Fatal exception, "
            "original ThreadProc from %s\n",
            pvThreadProc, pszName
        );

        if (lpCustomFilter) {
            lpFilter = lpCustomFilter;

            dprint(
                "Using custom exception filter for %s: %p\n",
                pszName, lpCustomFilter
            );

        }
    } else {
        dprint(
            "ThreadUnhandledExceptionFilter (ThreadProc=%p); "
            "Handling fatal exception with filter %p\n",
            pvThreadProc, lpFilter
        );
    }

    if (lpFilter)
        lVerdict = lpFilter(pExceptionPointers);

    return lVerdict;
}

static DWORD WINAPI WrappedThreadRoutine(LPVOID lpThreadParameter)
{
    DWORD dwResult = 0;
    ORIGINAL_THREAD_ARGS OriginalThreadArgs;

    RtlCopyMemory(&OriginalThreadArgs, lpThreadParameter, sizeof(OriginalThreadArgs));
    LocalFree(lpThreadParameter);

    __try {
        dprint(
            "Thread wrapper [%p]: Calling original args: %p(%p) filter: %p\n",
            WrappedThreadRoutine,
            OriginalThreadArgs.lpOriginalRoutine,
            OriginalThreadArgs.lpOriginalParameter,
            OriginalThreadArgs.lpExceptionFilter
        );

        dwResult = OriginalThreadArgs.lpOriginalRoutine(
            OriginalThreadArgs.lpOriginalParameter
        );
    }
    __except(ThreadUnhandledExceptionFilter(
        GetExceptionCode(), GetExceptionInformation(),
        OriginalThreadArgs.lpOriginalRoutine,
        OriginalThreadArgs.lpExceptionFilter, EXCEPTION_CONTINUE_SEARCH
    )) {
        dprint(
            "Thread wrapper with original args: %p(%p) fatal error "
            "and will die, but we'll try to countine\n",
            OriginalThreadArgs.lpOriginalRoutine,
            OriginalThreadArgs.lpOriginalParameter
        );

        return (DWORD)(-1);
    }

    dprint("Thread wrapper exited (%p)\n", OriginalThreadArgs.lpOriginalRoutine);
    return dwResult;
}

HANDLE CALLBACK MyCreateThread(
  LPSECURITY_ATTRIBUTES   lpThreadAttributes,
  SIZE_T                  dwStackSize,
  LPTHREAD_START_ROUTINE  lpStartAddress,
  LPVOID                  lpParameter,
  DWORD                   dwCreationFlags,
  LPDWORD                 lpThreadId
)
{
    PORIGINAL_THREAD_ARGS pOriginalArgsCopy = LocalAlloc(
        LMEM_FIXED, sizeof(ORIGINAL_THREAD_ARGS)
    );

    dprint(
        "MyCreateThread(func=%p, args=%p eh=%p)\n",
        lpStartAddress, lpParameter, lpDefaultExceptionHandler
    );

    if (pOriginalArgsCopy) {
        pOriginalArgsCopy->lpOriginalRoutine = lpStartAddress;
        pOriginalArgsCopy->lpOriginalParameter = lpParameter;
        pOriginalArgsCopy->lpExceptionFilter = lpDefaultExceptionHandler;

        lpStartAddress = WrappedThreadRoutine;
        lpParameter = (PVOID) pOriginalArgsCopy;
    } else {
        dprint("MyCreateThread: LocalAlloc failed\n");
    }

    return CreateThread(
        lpThreadAttributes, dwStackSize, lpStartAddress,
        lpParameter, dwCreationFlags, lpThreadId
    );
}

VOID MyEnumerateLibraries(LibraryInfoCb_t callback, PVOID pvCallbackData)
{
    PHCUSTOMLIBRARY module, tmp;

    if (!callback)
        return;

    dprint("Enumerating libraries: %p\n", libraries);
    dprint("By Module hashmap: %p\n", libraries->by_module);

    HASH_ITER(by_module, libraries->by_module, module, tmp) {
        PVOID pvBaseAddress = NULL;
        ULONG ulSize = 0;

        dprint("GetMemoryModuleInfo: Try: %p\n", module);

        if (GetMemoryModuleInfo(module->module, &pvBaseAddress, &ulSize)) {
            dprint(
                "GetMemoryModuleInfo %p: name=%s base=%p size=%u callback=%p\n",
                module, module->name, pvBaseAddress, ulSize, callback
            );

            if (!callback(pvCallbackData, module->name, pvBaseAddress, ulSize)) {
                dprint("GetMemoryModuleInfo: break requested\n");
                break;
            }

            dprint("GetMemoryModuleInfo: continue\n");
        } else {
            dprint("GetMemoryModuleInfo failed for %p\n", module);
        }
    }

    dprint("Enumerating libraries: %p - complete\n", libraries);
}

BOOL MyFindMemoryModuleNameByAddr(
    PVOID pvAddress, LPCSTR *ppszName, PVOID *ppvBaseAddress,
    LPTOP_LEVEL_EXCEPTION_FILTER *pehFilter
) {
    PHCUSTOMLIBRARY module = _FindMemoryModuleByAddress(
        pvAddress, ppvBaseAddress
    );

    if (!module) {
        return FALSE;
    }

    if (ppszName)
        *ppszName = module->name;

    if (pehFilter)
        *pehFilter = module->ehFilter;

    return TRUE;
}
