#ifndef GENERALLOADLIBRARY_H
#define GENERALLOADLIBRARY_H

#include <windows.h>

#ifndef CALLBACK
#define CALLBACK WINAPI
#endif

HMODULE MyLoadLibrary(LPCSTR, void *, void *);
HMODULE MyLoadLibraryEx(LPCSTR, void *, void *, BOOL);

HMODULE CALLBACK MyLoadLibraryA(LPCSTR);
HMODULE CALLBACK MyLoadLibraryW(LPCWSTR);
HMODULE CALLBACK MyLoadLibraryExA(LPCSTR name, HANDLE hFile, DWORD dwFlags);
HMODULE CALLBACK MyLoadLibraryExW(LPCWSTR name, HANDLE hFile, DWORD dwFlags);
HMODULE CALLBACK MyGetModuleHandleA(LPCSTR name);
HMODULE CALLBACK MyGetModuleHandleW(LPCWSTR name);
FARPROC CALLBACK MyGetProcAddress(HMODULE, LPCSTR);
BOOL CALLBACK MyFreeLibrary(HMODULE module);

FARPROC MyFindProcAddress(LPCSTR modulename, LPCSTR procname);

VOID MySetLibraries(PVOID pLibraries);
PVOID MyGetLibraries();

BOOL SetAliasedModule(HMODULE, HMODULE, const PSTR*, const PSTR*);

#ifndef DLL_QUERY_HMODULE
#define DLL_QUERY_HMODULE 6
#endif

#endif
