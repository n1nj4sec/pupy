/*
 * Memory DLL loading code
 * Version 0.0.4
 *
 * Copyright (c) 2004-2015 by Joachim Bauch / mail@joachim-bauch.de
 * http://www.joachim-bauch.de
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is MemoryModule.h
 *
 * The Initial Developer of the Original Code is Joachim Bauch.
 *
 * Portions created by Joachim Bauch are Copyright (C) 2004-2015
 * Joachim Bauch. All Rights Reserved.
 *
 */

#ifndef __MEMORY_MODULE_HEADER
#define __MEMORY_MODULE_HEADER

#include <windows.h>

typedef void *HMEMORYMODULE;

typedef void *HMEMORYRSRC;

typedef void *HCUSTOMMODULE;

#ifdef __cplusplus
extern "C" {
#endif

typedef HMODULE (*CustomGetModuleHandleA)(LPCSTR);
typedef HMODULE (*CustomGetModuleHandleW)(LPCWSTR);
typedef HMODULE (*CustomLoadLibraryExA)(LPCSTR, HANDLE, DWORD);
typedef HMODULE (*CustomLoadLibraryExW)(LPCWSTR, HANDLE, DWORD);
typedef HCUSTOMMODULE (*CustomLoadLibraryW)(LPCWSTR);
typedef HCUSTOMMODULE (*CustomLoadLibraryA)(LPCSTR);
typedef FARPROC (*CustomGetProcAddress)(HCUSTOMMODULE, LPCSTR);
typedef void (*CustomFreeLibraryFunc)(HCUSTOMMODULE);

/**
 * Load EXE/DLL from memory location.
 *
 * All dependencies are resolved using default LoadLibrary/GetProcAddress
 * calls through the Windows API.
 */
HMEMORYMODULE MemoryLoadLibrary(const void *);

typedef struct {
    CustomLoadLibraryA loadLibraryA;
    CustomLoadLibraryW loadLibraryW;
    CustomLoadLibraryExA loadLibraryExA;
    CustomLoadLibraryExW loadLibraryExW;
    CustomGetModuleHandleA getModuleHandleA;
    CustomGetModuleHandleW getModuleHandleW;
    CustomGetProcAddress getProcAddress;
    CustomFreeLibraryFunc freeLibrary;
} DL_CALLBACKS, *PDL_CALLBACKS;

/**
 * Load EXE/DLL from memory location using custom dependency resolvers.
 *
 * Dependencies will be resolved using passed callback methods.
 */
HMEMORYMODULE MemoryLoadLibraryEx(const void *, PDL_CALLBACKS, void *);

/**
 * Get address of exported method. Supports loading both by name and by
 * ordinal value.
 */
FARPROC MemoryGetProcAddress(HMEMORYMODULE, LPCSTR);

/**
 * Free previously loaded EXE/DLL.
 */
void MemoryFreeLibrary(HMEMORYMODULE);

HMODULE MyGetModuleHandleA(LPCSTR name);
HMODULE MyGetModuleHandleW(LPCWSTR name);
HMODULE MyLoadLibraryA(LPCSTR name);
HMODULE MyLoadLibraryW(LPCWSTR name);

HMODULE MyLoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD  dwFlags);
HMODULE MyLoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD  dwFlags);

#ifdef __cplusplus
}
#endif

#endif  // __MEMORY_MODULE_HEADER
