#ifndef GENERALLOADLIBRARY_H
#define GENERALLOADLIBRARY_H

#include <windows.h>

#ifndef CALLBACK
#define CALLBACK WINAPI
#endif

HMODULE MyLoadLibrary(LPCSTR, void *, void *);
HMODULE MyLoadLibraryEx(LPCSTR, const PVOID, PVOID, PVOID, DWORD);

HMODULE CALLBACK MyLoadLibraryA(LPCSTR);
HMODULE CALLBACK MyLoadLibraryW(LPCWSTR);
HMODULE CALLBACK MyLoadLibraryExA(LPCSTR name, HANDLE hFile, DWORD dwFlags);
HMODULE CALLBACK MyLoadLibraryExW(LPCWSTR name, HANDLE hFile, DWORD dwFlags);
HMODULE CALLBACK MyGetModuleHandleA(LPCSTR name);
HMODULE CALLBACK MyGetModuleHandleW(LPCWSTR name);
DWORD CALLBACK MyGetModuleFileNameW(HMODULE, LPWSTR, DWORD);
DWORD CALLBACK MyGetModuleFileNameA(HMODULE, LPSTR, DWORD);
FARPROC CALLBACK MyGetProcAddress(HMODULE, LPCSTR);
BOOL CALLBACK MyFreeLibrary(HMODULE module);

HRSRC CALLBACK MyFindResourceA(HMODULE module, LPCSTR name, LPCSTR type);
HRSRC CALLBACK MyFindResourceW(HMODULE module, LPCWSTR name, LPCWSTR type);
HRSRC CALLBACK MyFindResourceExA(HMODULE hModule, LPCSTR name, LPCSTR type, WORD language);
HRSRC CALLBACK MyFindResourceExW(HMODULE hModule, LPCWSTR name, LPCWSTR type, WORD language);
DWORD CALLBACK MySizeofResource(HMODULE module, HRSRC resource);
LPVOID CALLBACK MyLoadResource(HMODULE module, HRSRC resource);
int CALLBACK MyLoadStringA(HMODULE module, UINT id, LPSTR buffer, int maxsize);
int CALLBACK MyLoadStringW(HMODULE module, UINT id, LPWSTR buffer, int maxsize);

FARPROC MyFindProcAddress(LPCSTR modulename, LPCSTR procname);

VOID MySetLibraries(PVOID pLibraries);
PVOID MyGetLibraries();

typedef BOOL (*LibraryInfoCb_t) (
    PVOID pvCallbackData, LPCSTR pszName, PVOID pvBaseImage, ULONG ulSize
);

VOID MyEnumerateLibraries(LibraryInfoCb_t callback, PVOID pvCallbackData);

#ifndef DLL_QUERY_HMODULE
#define DLL_QUERY_HMODULE 6
#endif

#endif
