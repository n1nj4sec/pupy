#ifndef GENERALLOADLIBRARY_H
#define GENERALLOADLIBRARY_H

#include <windows.h>

HMODULE MyLoadLibrary(LPCSTR, void *, void *);
HMODULE MyLoadLibraryEx(LPCSTR, void *, void *, BOOL);

HMODULE MyGetModuleHandle(LPCSTR);
BOOL MyFreeLibrary(HMODULE);

HMODULE MyLoadLibraryA(LPCSTR);
HMODULE MyLoadLibraryW(LPCWSTR);

FARPROC MyGetProcAddress(HMODULE, LPCSTR);
FARPROC MyFindProcAddress(LPCSTR modulename, LPCSTR procname);

VOID MySetLibraries(PVOID pLibraries);
PVOID MyGetLibraries();

BOOL SetAliasedModule(HMODULE, HMODULE, const PSTR*, const PSTR*);

#ifndef DLL_QUERY_HMODULE
#define DLL_QUERY_HMODULE 6
#endif

#endif
