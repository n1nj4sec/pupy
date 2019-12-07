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

typedef HMODULE (CALLBACK *CustomGetModuleHandleA)(LPCSTR);
typedef HMODULE (CALLBACK *CustomGetModuleHandleW)(LPCWSTR);
typedef HMODULE (CALLBACK *CustomLoadLibraryExA)(LPCSTR, HANDLE, DWORD);
typedef HMODULE (CALLBACK *CustomLoadLibraryExW)(LPCWSTR, HANDLE, DWORD);
typedef HCUSTOMMODULE (CALLBACK *CustomLoadLibraryA)(LPCSTR);
typedef HCUSTOMMODULE (CALLBACK *CustomLoadLibraryW)(LPCWSTR);


typedef DWORD (CALLBACK *CustomGetModuleFileNameA)(HMODULE, LPSTR, DWORD);
typedef DWORD (CALLBACK *CustomGetModuleFileNameW)(HMODULE, LPWSTR, DWORD);

typedef HRSRC (CALLBACK *CustomFindResourceA)(HMEMORYMODULE module, LPCSTR name, LPCSTR type);
typedef HRSRC (CALLBACK *CustomFindResourceW)(HMEMORYMODULE module, LPCWSTR name, LPCWSTR type);

typedef HRSRC (CALLBACK *CustomFindResourceExA)(HMEMORYMODULE hModule, LPCSTR name, LPCSTR type, WORD language);
typedef HRSRC (CALLBACK *CustomFindResourceExW)(HMEMORYMODULE hModule, LPCWSTR name, LPCWSTR type, WORD language);

typedef DWORD (CALLBACK *CustomSizeofResource)(HMEMORYMODULE module, HRSRC resource);
typedef LPVOID (CALLBACK *CustomLoadResource)(HMEMORYMODULE module, HRSRC resource);

typedef FARPROC (CALLBACK *CustomGetProcAddress)(HMODULE, LPCSTR);
typedef void (CALLBACK *CustomFreeLibraryFunc)(HMODULE);

#ifdef _PUPY_PRIVATE_WS2_32
typedef NTSTATUS (CALLBACK *CustomEtwRegister) (
    LPCGUID            ProviderId,
    PVOID EnableCallback,
    PVOID              CallbackContext,
    PULONGLONG         RegHandle
);

typedef ULONG (CALLBACK *CustomEtwEventWrite) (
    ULONGLONG RegHandle,
    PVOID EventDescriptor,
    ULONG UserDataCount,
    PVOID UserData
);

typedef ULONG (CALLBACK *CustomEtwEventWriteFull) (
    ULONGLONG RegHandle,
    PVOID EventDescriptor,
    USHORT EventProperty,
    LPCGUID ActivityId,
    LPCGUID RelatedActivityId,
    ULONG UserDataCount,
    PVOID UserData
);

typedef NTSTATUS (CALLBACK *CustomEtwUnregister) (
    ULONGLONG RegHandle
);
#endif

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
    CustomGetModuleFileNameA getModuleFileNameA;
    CustomGetModuleFileNameW getModuleFileNameW;
    CustomGetProcAddress getProcAddress;
    CustomFreeLibraryFunc freeLibrary;

    CustomFindResourceA getFindResourceA;
    CustomFindResourceW getFindResourceW;
    CustomFindResourceExA getFindResourceExA;
    CustomFindResourceExW getFindResourceExW;
    CustomSizeofResource getSizeofResource;
    CustomLoadResource getLoadResource;

    CustomGetProcAddress systemGetProcAddress;
    CustomGetModuleFileNameA systemGetModuleFileNameA;
    CustomGetModuleFileNameW systemGetModuleFileNameW;
    CustomFindResourceExW systemFindResourceExW;
    CustomSizeofResource systemSizeofResource;
    CustomLoadResource systemLoadResource;

#ifdef _PUPY_PRIVATE_WS2_32
    CustomEtwRegister systemEtwRegister;
    CustomEtwEventWrite systemEtwEventWrite;
    CustomEtwEventWriteFull systemEtwEventWriteFull;
    CustomEtwUnregister systemEtwUnregister;
#endif
} DL_CALLBACKS, *PDL_CALLBACKS;

typedef enum {
    MEMORY_LOAD_DEFAULT = 0,
    MEMORY_LOAD_NO_EP = 1 << 0,
    MEMORY_LOAD_NO_TLS_CALLBACKS = 1 << 1,
    MEMORY_LOAD_NO_EXCEPTION_HANDLING = 1 << 2,
    MEMORY_LOAD_FROM_HMODULE = 1 << 3,
    MEMORY_LOAD_ALIASED = 1 << 4,
    MEMORY_LOAD_UNHOOK = 1 << 5,
    MEMORY_LOAD_EXPORT_FILTER_FNV1A = 1 << 6,
    MEMORY_LOAD_EXPORT_FILTER_PREFIX = 1 << 7,
} MEMORY_LOAD_FLAGS;

/**
 * Load EXE/DLL from memory location using custom dependency resolvers.
 *
 * Dependencies will be resolved using passed callback methods.
 */
HMEMORYMODULE MemoryLoadLibraryEx(
    const void *pvData,
    PDL_CALLBACKS pdlCallbacks,
    void *pvDllMainReserved,
    void *pvExportFilter,
    MEMORY_LOAD_FLAGS flags
);

/**
 * Get address of exported method. Supports loading both by name and by
 * ordinal value.
 */
FARPROC MemoryGetProcAddress(HMEMORYMODULE, LPCSTR);

/**
 * Free previously loaded EXE/DLL.
 */
void MemoryFreeLibrary(HMEMORYMODULE);

DWORD MemoryModuleFileNameA(HMODULE, LPSTR, DWORD);
DWORD MemoryModuleFileNameW(HMODULE, LPWSTR, DWORD);

HMEMORYRSRC MemoryFindResourceA(HMEMORYMODULE module, LPCSTR name, LPCSTR type);
HMEMORYRSRC MemoryFindResourceW(HMEMORYMODULE module, LPCWSTR name, LPCWSTR type);

HMEMORYRSRC MemoryFindResourceExA(HMEMORYMODULE hModule, LPCSTR name, LPCSTR type, WORD language);
HMEMORYRSRC MemoryFindResourceExW(HMEMORYMODULE hModule, LPCWSTR name, LPCWSTR type, WORD language);

DWORD MemorySizeofResource(HMEMORYMODULE module, HMEMORYRSRC resource);
LPVOID MemoryLoadResource(HMEMORYMODULE module, HMEMORYRSRC resource);

#ifdef __cplusplus
}
#endif

#endif  // __MEMORY_MODULE_HEADER
