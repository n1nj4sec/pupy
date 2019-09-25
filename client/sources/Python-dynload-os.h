#ifndef PYTHON_DYNLOAD_OS_H
#define PYTHON_DYNLOAD_OS_H

#include <windows.h>

#include "MyLoadLibrary.h"
#include "MemoryModule.h"
#include "resource_python_manifest.c"
#include "actctx.h"

#define FILE_SYSTEM_ENCODING "mbcs"

#ifndef PATH_MAX
#define PATH_MAX 260
#endif

typedef FARPROC (WINAPI *resolve_symbol_t) (HMODULE hModule, const char *name);

static char *OSGetProgramName() {
    static const char *program_name = "";
    static BOOL is_set = FALSE;

    wchar_t exe[PATH_MAX];
    int retval;

    if (is_set)
        return program_name;

    if (!GetModuleFileNameW(NULL, exe, PATH_MAX))
        return NULL;

    retval = WideCharToMultiByte(
        CP_UTF8, 0, exe, -1, NULL,
        0, NULL, NULL
    );

    if (!SUCCEEDED(retval))
        return NULL;

    program_name = LocalAlloc(LMEM_FIXED, retval);
    if (!program_name)
        return NULL;

    retval = WideCharToMultiByte(
        CP_UTF8, 0, exe, -1, program_name,
        retval, NULL, NULL
    );

    if (!SUCCEEDED(retval)) {
        LocalFree(program_name);
        return NULL;
    }

    is_set = TRUE;
    return program_name;
}

static HMODULE OSLoadLibrary(const char *dllname) {
    HMODULE hModule = NULL;
    hModule = GetModuleHandle(dllname);
    if (!hModule)
        hModule = LoadLibrary(dllname);

    return hModule;
}

#define OSResolveSymbol MyGetProcAddress

static HMODULE MemLoadLibrary(const char *dllname, char *bytes, size_t size, void *arg) {
    ULONG_PTR cookie = _My_ActivateActCtx();
    HMODULE hModule = MyLoadLibrary(dllname, bytes, arg);
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