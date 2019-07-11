#ifndef PYTHON_DYNLOAD_OS_H
#define PYTHON_DYNLOAD_OS_H

#include "MyLoadLibrary.h"
#include "MemoryModule.h"
#include "resource_python_manifest.c"
#include "actctx.h"

#define FILE_SYSTEM_ENCODING "mbcs"

#ifndef PATH_MAX
#define PATH_MAX 260
#endif

typedef FARPROC (*resolve_symbol_t) (HMODULE hModule, const char *name);

static HMODULE OSLoadLibrary(const char *dllname) {
    HMODULE hModule = NULL;
    hModule = GetModuleHandle(dllname);
    if (!hModule)
        hModule = LoadLibrary(dllname);

    return hModule;
}

#define OSResolveSymbol MyGetProcAddress

static HMODULE MemLoadLibrary(const char *dllname, char *bytes, size_t size) {
    ULONG_PTR cookie = _My_ActivateActCtx();
    HMODULE hModule = MyLoadLibrary(dllname, bytes, NULL);
    _My_DeactivateActCtx(cookie);
    return hModule;
}

#define MemResolveSymbol MyGetProcAddress
#define CheckLibraryLoaded GetModuleHandle

#define OSUnmapRegion(start, size) do {} while(0)

#define DEPENDENCIES { \
        { \
            "msvcr90.dll", \
            msvcr90_c_start, msvcr90_c_size, FALSE \
        }, \
        { \
            "python27.dll", \
            python27_c_start, python27_c_size, TRUE \
        } \
    }

#include "msvcr90.c"
#include "python27.c"

#endif // PYTHON_DYNLOAD_OS_H