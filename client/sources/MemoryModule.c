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
 * The Original Code is MemoryModule.c
 *
 * The Initial Developer of the Original Code is Joachim Bauch.
 *
 * Portions created by Joachim Bauch are Copyright (C) 2004-2015
 * Joachim Bauch. All Rights Reserved.
 *
 */

#include <windows.h>
#include <stddef.h>
#include <tchar.h>
#include "debug.h"
#include "uthash.h"

#ifndef IMAGE_SIZEOF_BASE_RELOCATION
// Vista SDKs no longer define IMAGE_SIZEOF_BASE_RELOCATION!?
#define IMAGE_SIZEOF_BASE_RELOCATION (sizeof(IMAGE_BASE_RELOCATION))
#endif

#include "MemoryModule.h"

HMEMORYRSRC _MemoryFindResourceW(HMEMORYMODULE module, LPCWSTR name, LPCWSTR type);
static PIMAGE_RESOURCE_DIRECTORY_ENTRY _MemorySearchResourceEntry(
    void *root,
    PIMAGE_RESOURCE_DIRECTORY resources,
    LPCWSTR key);
HMEMORYRSRC _MemoryFindResourceExW(HMEMORYMODULE hModule, LPCWSTR name, LPCWSTR type, WORD language);
DWORD _MemorySizeofResource(HMEMORYMODULE module, HMEMORYRSRC resource);
LPVOID _MemoryLoadResource(HMEMORYMODULE module, HMEMORYRSRC resource);
int _MemoryLoadString(HMEMORYMODULE module, UINT id, LPWSTR buffer, int maxsize);
int _MemoryLoadStringEx(HMEMORYMODULE module, UINT id, LPWSTR buffer, int maxsize, WORD language);

typedef BOOL (WINAPI *DllEntryProc)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);
typedef int (WINAPI *ExeEntryProc)(void);

static void*
OffsetPointer(void* data, ptrdiff_t offset) {
    return (void*) ((uintptr_t) data + offset);
}

typedef NTSTATUS (WINAPI *t_RtlGetVersion)(OSVERSIONINFOEXW *infow);

static NTSTATUS WINAPI RtlGetVersion(OSVERSIONINFOEXW *infow) {
    static t_RtlGetVersion _RtlGetVersion = NULL;
    if (!_RtlGetVersion) {
        HMODULE ntdll = GetModuleHandle("NTDLL");
        _RtlGetVersion = (t_RtlGetVersion) GetProcAddress(ntdll, "RtlGetVersion");
    }

    if (!_RtlGetVersion) {
        return E_UNEXPECTED;
    }

    return _RtlGetVersion(infow);
}

typedef struct {
    const char *name;
    FARPROC proc;
    UT_hash_handle hh;
} FUNCHASH;

typedef struct {
    DWORD dwFunctionsCount;
    DWORD dwBase;
    FARPROC *fpFunctions;
} FUNCIDX;

typedef struct {
    const char *symbol;
    FARPROC addr;
} ImportHooks;

typedef struct {
    const char *dllname;
    ImportHooks *hooks;
} DllHooks;

typedef struct {
    HCUSTOMMODULE *modules;
    FUNCIDX exports;
    FUNCHASH *phExportsIndex;

    int numModules;

    BOOL initialized;
    BOOL isDLL;
    BOOL isRelocated;
    DWORD pageSize;

    PIMAGE_NT_HEADERS headers;
    unsigned char *codeBase;

    HMODULE hOriginalModule;
    HMODULE hAliasedModule;
    PDL_CALLBACKS callbacks;

    PVOID pvExportFilter;
    MEMORY_LOAD_FLAGS flags;

    ExeEntryProc exeEntry;
    DllEntryProc pcDllEntry;

    unsigned char *resources;
} MEMORYMODULE, *PMEMORYMODULE;

typedef struct {
    LPVOID address;
    LPVOID alignedAddress;
    DWORD size;
    DWORD characteristics;
    BOOL last;
} SECTIONFINALIZEDATA, *PSECTIONFINALIZEDATA;

#define GET_HEADER_DICTIONARY(module, idx)  &(module)->headers->OptionalHeader.DataDirectory[idx]
#define ALIGN_DOWN(address, alignment)      (LPVOID)((uintptr_t)(address) & ~((alignment) - 1))

#ifdef DEBUG_OUTPUT
static void
OutputLastError(const char *msg)
{
    LPVOID tmp;
    char *tmpmsg;
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&tmp, 0, NULL);
    tmpmsg = (char *)LocalAlloc(LPTR, strlen(msg) + strlen(tmp) + 3);
    sprintf(tmpmsg, "%s: %s", msg, tmp);
    OutputDebugString(tmpmsg);
    LocalFree(tmpmsg);
    LocalFree(tmp);
}
#endif

static BOOL
CopySections(const unsigned char *data, PIMAGE_NT_HEADERS old_headers, PMEMORYMODULE module)
{
    int i, size;
    unsigned char *codeBase = module->codeBase;
    unsigned char *dest;
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(module->headers);
    for (i=0; i<module->headers->FileHeader.NumberOfSections; i++, section++) {
        if (section->SizeOfRawData == 0) {
            // section doesn't contain data in the dll itself, but may define
            // uninitialized data
            size = old_headers->OptionalHeader.SectionAlignment;
            if (size > 0) {
                dest = (unsigned char *)VirtualAlloc(codeBase + section->VirtualAddress,
                    size,
                    MEM_COMMIT,
                    PAGE_READWRITE);
                if (dest == NULL) {
                    return FALSE;
                }

                // Always use position from file to support alignments smaller
                // than page size.
                dest = codeBase + section->VirtualAddress;
                section->Misc.PhysicalAddress = (DWORD) (uintptr_t) dest;
                memset(dest, 0, size);
            }

            // section is empty
            continue;
        }

        // commit memory block and copy data from dll
        dest = (unsigned char *)VirtualAlloc(codeBase + section->VirtualAddress,
                            section->SizeOfRawData,
                            MEM_COMMIT,
                            PAGE_READWRITE);
        if (dest == NULL) {
            return FALSE;
        }

        // Always use position from file to support alignments smaller
        // than page size.
        dest = codeBase + section->VirtualAddress;
        memcpy(dest, data + section->PointerToRawData, section->SizeOfRawData);
        section->Misc.PhysicalAddress = (DWORD) (uintptr_t) dest;
    }

    return TRUE;
}

// Protection flags for memory pages (Executable, Readable, Writeable)
static int ProtectionFlags[2][2][2] = {
    {
        // not executable
        {PAGE_NOACCESS, PAGE_WRITECOPY},
        {PAGE_READONLY, PAGE_READWRITE},
    }, {
        // executable
        {PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY},
        {PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE},
    },
};

static DWORD
GetRealSectionSize(PMEMORYMODULE module, PIMAGE_SECTION_HEADER section) {
    DWORD size = section->SizeOfRawData;
    if (size == 0) {
        if (section->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) {
            size = module->headers->OptionalHeader.SizeOfInitializedData;
        } else if (section->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
            size = module->headers->OptionalHeader.SizeOfUninitializedData;
        }
    }
    return size;
}

static BOOL
FinalizeSection(PMEMORYMODULE module, PSECTIONFINALIZEDATA sectionData) {
    DWORD protect, oldProtect;
    BOOL executable;
    BOOL readable;
    BOOL writeable;

    if (sectionData->size == 0) {
        return TRUE;
    }

    if (sectionData->characteristics & IMAGE_SCN_MEM_DISCARDABLE) {
        // section is not needed any more and can safely be freed
        if (sectionData->address == sectionData->alignedAddress &&
            (sectionData->last ||
             module->headers->OptionalHeader.SectionAlignment == module->pageSize ||
             (sectionData->size % module->pageSize) == 0))
        {
            // Only allowed to decommit whole pages
            dprint(
                "VirtualFree: %p - %p (%lu)\n",
                sectionData->address, (PCHAR) sectionData->address + sectionData->size, sectionData->size
            );

            VirtualFree(sectionData->address, sectionData->size, MEM_DECOMMIT);
        }
        return TRUE;
    }

    // determine protection flags based on characteristics
    executable = (sectionData->characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    readable =   (sectionData->characteristics & IMAGE_SCN_MEM_READ) != 0;
    writeable =  (sectionData->characteristics & IMAGE_SCN_MEM_WRITE) != 0;
    protect = ProtectionFlags[executable][readable][writeable];
    if (sectionData->characteristics & IMAGE_SCN_MEM_NOT_CACHED) {
        protect |= PAGE_NOCACHE;
    }

    // change memory access flags
    dprint(
        "VirtualProtect: %p - %p (%lu) %08x\n",
        sectionData->address, (PCHAR) sectionData->address + sectionData->size, sectionData->size, protect
    );
    if (VirtualProtect(sectionData->address, sectionData->size, protect, &oldProtect) == 0) {
#ifdef DEBUG_OUTPUT
        OutputLastError("Error protecting memory page");
#endif
        return FALSE;
    }

    return TRUE;
}

static BOOL
FinalizeSections(PMEMORYMODULE module)
{
    int i;
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(module->headers);
#ifdef _WIN64
    uintptr_t imageOffset = (module->headers->OptionalHeader.ImageBase & 0xffffffff00000000);
#else
    #define imageOffset 0
#endif
    SECTIONFINALIZEDATA sectionData;
    sectionData.address = (LPVOID)((uintptr_t)section->Misc.PhysicalAddress | imageOffset);
    sectionData.alignedAddress = ALIGN_DOWN(sectionData.address, module->pageSize);
    sectionData.size = GetRealSectionSize(module, section);
    sectionData.characteristics = section->Characteristics;
    sectionData.last = FALSE;
    section++;

    // loop through all sections and change access flags
    for (i=1; i<module->headers->FileHeader.NumberOfSections; i++, section++) {
        LPVOID sectionAddress = (LPVOID)((uintptr_t)section->Misc.PhysicalAddress | imageOffset);
        LPVOID alignedAddress = ALIGN_DOWN(sectionAddress, module->pageSize);
        DWORD sectionSize = GetRealSectionSize(module, section);
        // Combine access flags of all sections that share a page
        // TODO(fancycode): We currently share flags of a trailing large section
        //   with the page of a first small section. This should be optimized.
        if (sectionData.alignedAddress == alignedAddress || (uintptr_t) sectionData.address + sectionData.size > (uintptr_t) alignedAddress) {
            // Section shares page with previous
            if ((section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0 || (sectionData.characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0) {
                sectionData.characteristics = (sectionData.characteristics | section->Characteristics) & ~IMAGE_SCN_MEM_DISCARDABLE;
            } else {
                sectionData.characteristics |= section->Characteristics;
            }
            sectionData.size = (((uintptr_t)sectionAddress) + sectionSize) - (uintptr_t) sectionData.address;
            continue;
        }

        if (!FinalizeSection(module, &sectionData)) {
            return FALSE;
        }

        sectionData.address = sectionAddress;
        sectionData.alignedAddress = alignedAddress;
        sectionData.size = sectionSize;
        sectionData.characteristics = section->Characteristics;
    }
    sectionData.last = TRUE;
    if (!FinalizeSection(module, &sectionData)) {
        return FALSE;
    }
#ifndef _WIN64
#undef imageOffset
#endif
    return TRUE;
}

static BOOL
ExecuteTLS(PMEMORYMODULE module)
{
    unsigned char *codeBase = module->codeBase;
    PIMAGE_TLS_DIRECTORY tls;
    PIMAGE_TLS_CALLBACK* callback;

    PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY(
        module, IMAGE_DIRECTORY_ENTRY_TLS);
    if (directory->VirtualAddress == 0) {
        return TRUE;
    }

    tls = (PIMAGE_TLS_DIRECTORY) (codeBase + directory->VirtualAddress);
    callback = (PIMAGE_TLS_CALLBACK *) tls->AddressOfCallBacks;
    if (callback) {
        while (*callback) {
            dprint("Call TLS Callback %p\n", callback);
            (*callback)((LPVOID) codeBase, DLL_PROCESS_ATTACH, NULL);
            callback++;
        }
    }
    return TRUE;
}

static BOOL
PerformBaseRelocation(PMEMORYMODULE module, SIZE_T delta)
{
    unsigned char *codeBase = module->codeBase;
    PIMAGE_BASE_RELOCATION relocation;

    PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY(module, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    if (directory->Size == 0) {
        return (delta == 0);
    }

    relocation = (PIMAGE_BASE_RELOCATION) (codeBase + directory->VirtualAddress);
    for (; relocation->VirtualAddress > 0; ) {
        DWORD i;
        unsigned char *dest = codeBase + relocation->VirtualAddress;
        unsigned short *relInfo = (unsigned short *)((unsigned char *)relocation + IMAGE_SIZEOF_BASE_RELOCATION);
        for (i=0; i<((relocation->SizeOfBlock-IMAGE_SIZEOF_BASE_RELOCATION) / 2); i++, relInfo++) {
            DWORD *patchAddrHL;
#ifdef _WIN64
            ULONGLONG *patchAddr64;
#endif
            int type, offset;

            // the upper 4 bits define the type of relocation
            type = *relInfo >> 12;
            // the lower 12 bits define the offset
            offset = *relInfo & 0xfff;

            switch (type)
            {
            case IMAGE_REL_BASED_ABSOLUTE:
                // skip relocation
                break;

            case IMAGE_REL_BASED_HIGHLOW:
                // change complete 32 bit address
                patchAddrHL = (DWORD *) (dest + offset);
                *patchAddrHL += (DWORD) delta;
                break;

#ifdef _WIN64
            case IMAGE_REL_BASED_DIR64:
                patchAddr64 = (ULONGLONG *) (dest + offset);
                *patchAddr64 += (ULONGLONG) delta;
                break;
#endif

            default:
                //printf("Unknown relocation: %d\n", type);
                break;
            }
        }

        // advance to next relocation block
        relocation = (PIMAGE_BASE_RELOCATION) (((char *) relocation) + relocation->SizeOfBlock);
    }
    return TRUE;
}

static FARPROC
GetImportAddr(
    ImportHooks *hooks, CustomGetProcAddress getProcAddress,
        HCUSTOMMODULE hModule, LPCSTR pszSymName)
{
    ImportHooks *iter;

    if (!hooks)
        return getProcAddress(hModule, pszSymName);

    for (iter = hooks; iter->symbol; iter ++) {
        if (!iter->addr)
            continue;

        if (!strcmp(iter->symbol, pszSymName)) {
            dprint("HOOK %s -> %p\n", pszSymName, iter->addr);
            return iter->addr;
        }
    }

    return getProcAddress(hModule, pszSymName);
}

static BOOL
BuildResourceTables(PMEMORYMODULE module)
{
    unsigned char *codeBase = ((PMEMORYMODULE) module)->codeBase;
    PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY(
        (PMEMORYMODULE) module, IMAGE_DIRECTORY_ENTRY_RESOURCE);
    PIMAGE_RESOURCE_DIRECTORY rootResources;

    if (directory->Size == 0) {
        module->resources = NULL;
        return TRUE;
    }

    module->resources = codeBase + directory->VirtualAddress;
    return TRUE;
}

static
BOOL CALLBACK
GetVersionExW_Hooked(OSVERSIONINFOEXW *info) {
    NTSTATUS ntResult = RtlGetVersion(info);
    return ntResult == S_OK;
}

static
BOOL CALLBACK
GetVersionExA_Hooked(OSVERSIONINFOEXA *info) {
    OSVERSIONINFOEXW infow;
    DWORD dwResult;
    NTSTATUS ntResult = RtlGetVersion(&infow);
    if (ntResult != S_OK)
        return FALSE;

    dwResult = WideCharToMultiByte(
        CP_OEMCP, 0, infow.szCSDVersion, -1, info->szCSDVersion,
        sizeof(info->szCSDVersion), NULL, NULL
    );

    if (!SUCCEEDED(dwResult))
        return FALSE;

    info->dwOSVersionInfoSize = infow.dwOSVersionInfoSize;
    info->dwMajorVersion = infow.dwMajorVersion;
    info->dwMinorVersion = infow.dwMinorVersion;
    info->dwBuildNumber = infow.dwBuildNumber;
    info->dwPlatformId = infow.dwPlatformId;
    info->wServicePackMajor = infow.wServicePackMajor;
    info->wServicePackMinor = infow.wServicePackMinor;
    info->wSuiteMask = infow.wSuiteMask;
    info->wProductType = infow.wProductType;
    info->wReserved = infow.wReserved;

    return TRUE;
}

static
ImportHooks* GetHooks(DllHooks *dllhooks, const char *dllName)
{
    DllHooks *iter;

    for (iter = dllhooks; iter->dllname; iter ++) {
        if (!_stricmp(iter->dllname, dllName)) {
            return iter->hooks;
        }
    }

    return NULL;
}


static BOOL
BuildImportTable(PMEMORYMODULE module)
{
    unsigned char *codeBase = module->codeBase;
    PIMAGE_IMPORT_DESCRIPTOR importDesc;
    BOOL result = TRUE;

    PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY(
        module, IMAGE_DIRECTORY_ENTRY_IMPORT);

    ImportHooks kernel32Hooks[] = {
        {"LoadLibraryA", (FARPROC) module->callbacks->loadLibraryA},
        {"LoadLibraryW", (FARPROC) module->callbacks->loadLibraryW},
        {"LoadLibraryExA", (FARPROC) module->callbacks->loadLibraryExA},
        {"LoadLibraryExW", (FARPROC) module->callbacks->loadLibraryExW},
        {"GetModuleHandleA", (FARPROC) module->callbacks->getModuleHandleA},
        {"GetModuleHandleW", (FARPROC) module->callbacks->getModuleHandleW},
        {"GetModuleFileNameA", (FARPROC) module->callbacks->getModuleFileNameA},
        {"GetModuleFileNameW", (FARPROC) module->callbacks->getModuleFileNameW},

        {"GetVersionExA", (FARPROC) GetVersionExA_Hooked},
        {"GetVersionExW", (FARPROC) GetVersionExW_Hooked},

        {"FindResourceA", (FARPROC) module->callbacks->getFindResourceA},
        {"FindResourceW", (FARPROC) module->callbacks->getFindResourceW},
        {"FindResourceExA", (FARPROC) module->callbacks->getFindResourceExA},
        {"FindResourceExW", (FARPROC) module->callbacks->getFindResourceExW},
        {"SizeofResource", (FARPROC) module->callbacks->getSizeofResource},
        {"LoadResource", (FARPROC) module->callbacks->getLoadResource},

        {"GetProcAddress", (FARPROC) module->callbacks->getProcAddress},
        {"FreeLibrary", (FARPROC) module->callbacks->freeLibrary},
        {NULL, NULL}
    };

#ifdef _PUPY_PRIVATE_WS2_32
    ImportHooks ntdllHooks[] = {
        {"EtwEventRegister", (FARPROC) module->callbacks->systemEtwRegister},
        {"EtwEventWrite", (FARPROC) module->callbacks->systemEtwEventWrite},
        {"EtwEventWriteFull", (FARPROC) module->callbacks->systemEtwEventWriteFull},
        {"EtwEventUnregister", (FARPROC) module->callbacks->systemEtwUnregister},
        {NULL, NULL}
    };

    ImportHooks advapi32Hooks[] = {
        {"EventRegister", (FARPROC) module->callbacks->systemEtwRegister},
        {"EventWrite", (FARPROC) module->callbacks->systemEtwEventWrite},
        {"EventWriteFull", (FARPROC) module->callbacks->systemEtwEventWriteFull},
        {"EventUnregister", (FARPROC) module->callbacks->systemEtwUnregister},
        {NULL, NULL}
    };
#endif

    DllHooks dllHooks[] = {
        { "KERNEL32.DLL", kernel32Hooks },
#ifdef _PUPY_PRIVATE_WS2_32
        { "ADVAPI32.DLL", advapi32Hooks },
        { "NTDLL.DLL", ntdllHooks },
#endif
        {NULL, NULL}
    };

    if (directory->Size == 0)
        return TRUE;

    dprint("Resolving imports\n");

    importDesc = (PIMAGE_IMPORT_DESCRIPTOR) (codeBase + directory->VirtualAddress);
    for (
        ;
        !IsBadReadPtr(importDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR)) && importDesc->Name; importDesc++
    ) {
        ImportHooks *hooks = NULL;
        uintptr_t *thunkRef;
        FARPROC *funcRef;
        HCUSTOMMODULE *tmp;
        HCUSTOMMODULE handle;
        LPCSTR lpcszLibraryName = (LPCSTR) (codeBase + importDesc->Name);

        dprint(
            "Import %s (LoadLibraryA = %p)\n",
            lpcszLibraryName,
            module->callbacks->loadLibraryA
        );

        handle = module->callbacks->loadLibraryA(lpcszLibraryName);

        dprint("Import %s -> %p\n", lpcszLibraryName, handle);

        if (!handle) {
            SetLastError(ERROR_MOD_NOT_FOUND);
            result = FALSE;
            break;
        }

        tmp = (HCUSTOMMODULE *) realloc(
            module->modules, (module->numModules+1)*(sizeof(HCUSTOMMODULE)));
        if (tmp == NULL) {
            module->callbacks->freeLibrary(handle);
            SetLastError(ERROR_OUTOFMEMORY);
            result = FALSE;
            break;
        }

        module->modules = tmp;
        module->modules[module->numModules++] = handle;

        if (importDesc->OriginalFirstThunk) {
            thunkRef = (uintptr_t *) (codeBase + importDesc->OriginalFirstThunk);
            funcRef = (FARPROC *) (codeBase + importDesc->FirstThunk);
            dprint("%s have hint table, offset=%lu\n",
                lpcszLibraryName, importDesc->OriginalFirstThunk);
        } else {
            // no hint table
            dprint("%s does not have hint table\n", lpcszLibraryName);
            thunkRef = (uintptr_t *) (codeBase + importDesc->FirstThunk);
            funcRef = (FARPROC *) (codeBase + importDesc->FirstThunk);
        }

        hooks = GetHooks(dllHooks, lpcszLibraryName);
        if (hooks) {
            dprint("Use hooks for %s: %p\n", lpcszLibraryName, hooks);
        }

        dprint("Resolving symbols.. (%p)\n", thunkRef);

        for (; thunkRef && *thunkRef; thunkRef++, funcRef++) {
            dprint("Thunk value: %p\n", *thunkRef);

            if (IMAGE_SNAP_BY_ORDINAL(*thunkRef)) {

                dprint("Import by thunk (%d)\n", IMAGE_ORDINAL(*thunkRef));

                *funcRef = module->callbacks->getProcAddress(
                    handle, (LPCSTR)IMAGE_ORDINAL(*thunkRef)
                );

                dprint("Import %d@%s -> %p\n",
                    IMAGE_ORDINAL(*thunkRef), lpcszLibraryName, *funcRef);

            } else {
                PIMAGE_IMPORT_BY_NAME thunkData = (PIMAGE_IMPORT_BY_NAME) (
                    codeBase + (*thunkRef));

                dprint("Import %s@%s -> ?\n",
                    (LPCSTR)&thunkData->Name, lpcszLibraryName);

                *funcRef = GetImportAddr(
                    hooks, module->callbacks->getProcAddress,
                    handle, (LPCSTR)&thunkData->Name
                );

                dprint("Import %s@%s -> %p\n",
                    (LPCSTR)&thunkData->Name, lpcszLibraryName, *funcRef);
            }

            if (!*funcRef) {
                result = FALSE;
                break;
            }
        }

        dprint("Resolving symbols %s -> complete, result=%p\n", lpcszLibraryName, result);

        if (!result) {
            module->callbacks->freeLibrary(handle);
            SetLastError(ERROR_PROC_NOT_FOUND);
            break;
        }
    }

    return result;
}

//===============================================================================================//
#if defined(_WIN64)
BOOL WINAPI RegisterExceptionTable(PMEMORYMODULE pModule)
{
    UINT_PTR uiLibraryAddress = 0;
    UINT_PTR uiAddressArray = 0;
    UINT_PTR uiNameArray    = 0;
    UINT_PTR uiNameOrdinals = 0;
    PIMAGE_NT_HEADERS pNtHeaders             = NULL;
    PIMAGE_DATA_DIRECTORY pDataDirectory     = NULL;
    PIMAGE_RUNTIME_FUNCTION_ENTRY pExceptionDirectory = NULL;
    DWORD dwCount;
    BOOL bResult;
    unsigned char *codeBase = pModule->codeBase;

    if( pModule == NULL )
        return FALSE;

    pDataDirectory = GET_HEADER_DICTIONARY(pModule, IMAGE_DIRECTORY_ENTRY_EXCEPTION);

    if (pDataDirectory->Size == 0 || pDataDirectory->VirtualAddress == 0)
        return TRUE;

    // get the VA of the export directory
    pExceptionDirectory = (PIMAGE_RUNTIME_FUNCTION_ENTRY)(codeBase + pDataDirectory->VirtualAddress);

    if (!pExceptionDirectory)
            return TRUE;

    dwCount = (pDataDirectory->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)) - 1;

    return RtlAddFunctionTable((PRUNTIME_FUNCTION)pExceptionDirectory, dwCount, (UINT_PTR)codeBase);
}
#endif

static
DWORD fnv1a(const unsigned char *ucData, size_t size) {
    size_t i;
    DWORD dwHash = 2166136261;
    for (i=0; i<size; i++) {
        dwHash ^= ucData[i];
        dwHash *= 16777619;
    }
    return dwHash;
}

static
BOOL isAllowedSymbol(LPCSTR procname, PVOID pvExportFilter, MEMORY_LOAD_FLAGS flags) {
    size_t proclen;

    if (HIWORD(procname) == 0) {
        return TRUE;
    }

    if (!pvExportFilter) {
        return TRUE;
    }

    proclen = strlen(procname);

    switch (flags & (MEMORY_LOAD_EXPORT_FILTER_FNV1A | MEMORY_LOAD_EXPORT_FILTER_PREFIX)) {
        case MEMORY_LOAD_DEFAULT: {
            const PSTR *pIter;
            for (pIter=pvExportFilter; pIter && *pIter; pIter++) {
                LPCSTR pSymbol = *pIter;
                if (!strcmp(pSymbol, procname)) {
                    dprint("Allow import %s - by symbol\n", procname);
                    return TRUE;
                }
            }
        }
        break;

        case MEMORY_LOAD_EXPORT_FILTER_FNV1A: {
            DWORD dwProcHash = fnv1a((const unsigned char *) procname, proclen);
            PDWORD pIter;
            for (pIter=pvExportFilter; pIter && *pIter; pIter++) {
                if (*pIter == dwProcHash) {
                    dprint("Allow import %s - by fnv1a (%08x)\n",
                        procname, dwProcHash);
                    return TRUE;
                }
            }
        }
        break;

        case MEMORY_LOAD_EXPORT_FILTER_PREFIX: {
            const PSTR *pIter;
            for (pIter=pvExportFilter; pIter && *pIter; pIter++) {
                LPCSTR pPrefix = *pIter;
                size_t len = strlen(pPrefix);

                if (len > proclen)
                    continue;

                if (!strncmp(pPrefix, procname, len)) {
                    dprint("Allow import %s - prefix '%s' (%d)\n",
                        procname, pPrefix, len);
                    return TRUE;
                }
            }
        }
        break;

        default:
            dprint("Invalid flags %08x\n", flags);
    }

    dprint("Deny import: %s\n", procname);
    return FALSE;
}

VOID BuildExportTable(PMEMORYMODULE module)
{
    unsigned char *codeBase = module->codeBase;
    DWORD i;
    PDWORD nameRef;
    PWORD ordinal;
    FUNCHASH *phIdx, *phExports = NULL;
    PIMAGE_EXPORT_DIRECTORY exports = NULL;
    PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY((PMEMORYMODULE)module, IMAGE_DIRECTORY_ENTRY_EXPORT);

    if (module->headers->OptionalHeader.AddressOfEntryPoint != 0) {
        if (module->isDLL) {
            module->pcDllEntry = (DllEntryProc) (module->codeBase +
                    module->headers->OptionalHeader.AddressOfEntryPoint);
            module->exeEntry = NULL;
        } else {
            module->pcDllEntry= NULL;
            module->exeEntry = (ExeEntryProc) (module->codeBase +
                module->headers->OptionalHeader.AddressOfEntryPoint);
        }
    }

    if (directory->Size)
        exports = (PIMAGE_EXPORT_DIRECTORY) (codeBase + directory->VirtualAddress);

    if (!(exports && exports->NumberOfNames &&
             exports->NumberOfFunctions)) {
        module->exports.dwFunctionsCount = 0;
        module->exports.fpFunctions = NULL;
        module->phExportsIndex = NULL;
        return;
    }

    module->exports.dwFunctionsCount = exports->NumberOfFunctions;
    module->exports.dwBase = exports->Base;
    module->exports.fpFunctions = (FARPROC*) malloc(
        exports->NumberOfFunctions * sizeof(FARPROC));

    // search function name in list of exported names
    nameRef = (DWORD *) (codeBase + exports->AddressOfNames);
    ordinal = (WORD *) (codeBase + exports->AddressOfNameOrdinals);

    for (i=0; i<exports->NumberOfNames; i++, nameRef++, ordinal++) {
        LPCSTR pcName = (LPCSTR) (codeBase + (*nameRef));
        DWORD dwIdx = *ordinal;
        FARPROC proc = NULL;

        if (dwIdx > exports->NumberOfFunctions)
            continue;

        if (!isAllowedSymbol(pcName, module->pvExportFilter, module->flags))
            continue;

        proc = (FARPROC) (
            codeBase + (*(DWORD *) (
                codeBase + exports->AddressOfFunctions + (dwIdx*4))));

        module->exports.fpFunctions[dwIdx] = proc;

        phIdx = (FUNCHASH*) malloc (sizeof(FUNCHASH));
        phIdx->name = strdup(pcName);
        phIdx->proc = proc;
        HASH_ADD_KEYPTR(
            hh, phExports, phIdx->name, strlen(phIdx->name), phIdx
        );
    }

    module->phExportsIndex = phExports;
}

DWORD SizeOfPEHeader(IMAGE_NT_HEADERS *headers)
{
    return offsetof(IMAGE_NT_HEADERS, OptionalHeader) +
        headers->FileHeader.SizeOfOptionalHeader +
        (headers->FileHeader.NumberOfSections * sizeof (IMAGE_SECTION_HEADER));
}

VOID CleanupHeaders(PMEMORYMODULE module) {
    PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY(
        module, IMAGE_DIRECTORY_ENTRY_EXPORT);

    dprint(
        "Cleaning PE headers at %p, size %d\n",
        module->headers, SizeOfPEHeader(module->headers));

    if (!VirtualFree(
        module->headers, SizeOfPEHeader(module->headers),
        MEM_DECOMMIT)) {
            dprint("Cleaning PE Header failed: %d\n", GetLastError());
        }
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

#define _ISSET(dw, x) ((dw) & (x))

HMEMORYMODULE MemoryLoadLibraryEx(
    const PVOID pvData,
    PDL_CALLBACKS pdlCallbacks,
    PVOID pvDllMainReserved,
    const PVOID pvExportFilter,
    MEMORY_LOAD_FLAGS flags
)
{
    PMEMORYMODULE result = NULL;
    PIMAGE_DOS_HEADER dos_header;
    PIMAGE_NT_HEADERS old_header;
    unsigned char *code = NULL;
    unsigned char *headers = NULL;
    SIZE_T locationDelta;
    SYSTEM_INFO sysInfo;
    HMODULE hModule;
    HMODULE hOriginalModule = NULL;
    HMODULE hAliasedModule = NULL;
    HANDLE hMapping = INVALID_HANDLE_VALUE;
    const void *pvViewOfFile = NULL;
    const unsigned char *data = NULL;

    if (!pdlCallbacks) {
        dprint("No callbacks!\n");
        return NULL;
    }

    if (_ISSET(flags, MEMORY_LOAD_FROM_HMODULE | MEMORY_LOAD_UNHOOK)) {
        hOriginalModule = (HMODULE) pvData;
        if (!_CreateModuleMapping(hOriginalModule, &hMapping, &pvViewOfFile)) {
            dprint("MemoryLoadLibraryEx: Failed to mmap original module\n");
            SetLastError(ERROR_OUTOFMEMORY);
            return NULL;
        }

        data = pvViewOfFile;
    } else {
        data = (const unsigned char *) pvData;
    }

    dprint("MemoryLoadLibraryEx: Load from %p\n", data);

    dos_header = (PIMAGE_DOS_HEADER)data;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        SetLastError(ERROR_BAD_EXE_FORMAT);
        goto cleanup;
    }

    old_header = (PIMAGE_NT_HEADERS)&((const unsigned char *)(data))[dos_header->e_lfanew];
    if (old_header->Signature != IMAGE_NT_SIGNATURE) {
        SetLastError(ERROR_BAD_EXE_FORMAT);
        goto cleanup;
    }

#ifdef _WIN64
    if (old_header->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
#else
    if (old_header->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
#endif
        SetLastError(ERROR_BAD_EXE_FORMAT);
        goto cleanup;
    }

    if (old_header->OptionalHeader.SectionAlignment & 1) {
        // Only support section alignments that are a multiple of 2
        SetLastError(ERROR_BAD_EXE_FORMAT);
        goto cleanup;
    }

#if DEBUG
    // reserve memory for image of library
    // XXX: is it correct to commit the complete memory region at once?
    //      calling DllEntry raises an exception if we don't...
    code = (unsigned char *)VirtualAlloc((LPVOID)(old_header->OptionalHeader.ImageBase),
        old_header->OptionalHeader.SizeOfImage,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE);
#endif

    if (code == NULL) {
        // try to allocate memory at arbitrary position
        code = (unsigned char *)VirtualAlloc(NULL,
            old_header->OptionalHeader.SizeOfImage,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE);
        if (code == NULL) {
            SetLastError(ERROR_OUTOFMEMORY);
            dprint("Can't allocate base image\n");
            goto cleanup;
        }
    }

    dprint("ImageBase: %p\n", code);

    result = (PMEMORYMODULE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(MEMORYMODULE));
    if (result == NULL) {
        VirtualFree(code, 0, MEM_RELEASE);
        SetLastError(ERROR_OUTOFMEMORY);
        goto cleanup;
    }

    result->codeBase = code;
    result->isDLL = (old_header->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;

    result->callbacks = pdlCallbacks;
    result->flags = flags;
    result->pvExportFilter = pvExportFilter;
    result->hOriginalModule = hOriginalModule;
    if (_ISSET(flags, MEMORY_LOAD_ALIASED)) {
        result->hAliasedModule = (HMODULE) pvDllMainReserved;
    }

    GetNativeSystemInfo(&sysInfo);

    result->pageSize = sysInfo.dwPageSize;

    // commit memory for headers
    headers = (unsigned char *)VirtualAlloc(code,
        old_header->OptionalHeader.SizeOfHeaders,
        MEM_COMMIT,
        PAGE_READWRITE);

    // copy PE header to code
    memcpy(headers, dos_header, old_header->OptionalHeader.SizeOfHeaders);
    result->headers = (PIMAGE_NT_HEADERS)&((const unsigned char *)(headers))[dos_header->e_lfanew];

    // update position
    result->headers->OptionalHeader.ImageBase = (uintptr_t)code;

    // copy sections from DLL file block to new memory location
    if (!CopySections((const unsigned char *) data, old_header, result)) {
        goto error;
    }

    // adjust base address of imported data
    locationDelta = (SIZE_T)(code - old_header->OptionalHeader.ImageBase);
    if (locationDelta != 0) {
        result->isRelocated = PerformBaseRelocation(result, locationDelta);
    } else {
        result->isRelocated = TRUE;
    }

    // Save Resources VA
    if (!BuildResourceTables(result)) {
        goto error;
    }

    // load required dlls and adjust function table of imports
    dprint("Build import table..\n");
    if (!BuildImportTable(result)) {
        goto error;
    }

    // mark memory pages depending on section headers and release
    // sections that are marked as "discardable"
    dprint("Finalize sections..\n");
    if (!FinalizeSections(result)) {
        goto error;
    }

    // TLS callbacks are executed BEFORE the main loading
    if (!_ISSET(flags, MEMORY_LOAD_NO_TLS_CALLBACKS)) {
        dprint("Execute TLS..\n");
        if (!ExecuteTLS(result)) {
            goto error;
        }
    }

#ifdef _WIN64
    if (!_ISSET(flags, MEMORY_LOAD_NO_EXCEPTION_HANDLING)) {
        // Enable exceptions
        dprint("Register Exception table..\n");
        if (!RegisterExceptionTable(result)) {
            goto error;
        }
    }
#endif

    // Build functions table
    dprint("Build export table..\n");
    BuildExportTable(result);

    // get entry point of loaded library
    if (!_ISSET(flags, MEMORY_LOAD_NO_EP) &&
            result->isDLL && result->pcDllEntry)
    {
        BOOL successfull;

        dprint(
            "Execute EP (ImageBase: %p EP: %p ARG: %p)..\n",
            code, result->pcDllEntry, pvDllMainReserved
        );

        // notify library about attaching to process
        successfull = result->pcDllEntry(
            (HINSTANCE)code, DLL_PROCESS_ATTACH,
            _ISSET(flags, MEMORY_LOAD_ALIASED) ? NULL : pvDllMainReserved
        );

        if (!successfull) {
            SetLastError(ERROR_DLL_INIT_FAILED);
            goto error;
        }
        result->initialized = TRUE;
    }

    dprint("MemoryLoadLibraryEx: Library loaded\n");

#ifndef DEBUG
    // Cleanup PE headers
    CleanupHeaders(result);

    dprint("MemoryLoadLibraryEx: headers cleaned up\n");
#endif

cleanup:
    if (pvViewOfFile)
        UnmapViewOfFile(pvViewOfFile);

    if (hMapping != INVALID_HANDLE_VALUE)
        CloseHandle(hMapping);

    return (HMEMORYMODULE)result;

error:
    dprint("MemoryLoadLibraryEx: error\n");
    // cleanup
    MemoryFreeLibrary(result);

    if (pvViewOfFile)
        UnmapViewOfFile(pvViewOfFile);

    if (hMapping != INVALID_HANDLE_VALUE)
        CloseHandle(hMapping);

    return NULL;
}

static
FARPROC _MemoryGetProcAddress(PMEMORYMODULE module, LPCSTR name)
{
    if (!module || !module->exports.dwFunctionsCount) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return NULL;
    }

    if (HIWORD(name) == 0) {
        DWORD idx;
        // load function by ordinal value
        if (LOWORD(name) < module->exports.dwBase) {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return NULL;
        }

        idx = LOWORD(name) - module->exports.dwBase;
        if (idx > module->exports.dwFunctionsCount) {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return NULL;
        }

        return module->exports.fpFunctions[idx];
    } else {
        FUNCHASH *phIdx;
        HASH_FIND_STR(module->phExportsIndex, name, phIdx);

        if (!phIdx) {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return NULL;
        }

        return phIdx->proc;
    }
}

FARPROC MemoryGetProcAddress(HMEMORYMODULE hmodule, LPCSTR name)
{
    PMEMORYMODULE module = (PMEMORYMODULE) hmodule;
    FARPROC fpAddress;

    if (!module)
        return NULL;

    fpAddress = _MemoryGetProcAddress(module, name);

    if (!fpAddress && module->hAliasedModule) {
        dprint(
            "MemoryGetProcAddress fallback aliased -> %p\n",
            module->hAliasedModule
        );
        fpAddress = module->callbacks->systemGetProcAddress(
            module->hAliasedModule, name
        );
    }

    if (!fpAddress && module->hOriginalModule) {
        dprint(
            "MemoryGetProcAddress fallback -> %p\n",
            module->hOriginalModule
        );
        fpAddress = module->callbacks->systemGetProcAddress(
            module->hOriginalModule, name
        );
    }

    return fpAddress;
}


DWORD MemoryModuleFileNameA(HMODULE hModule, LPSTR name, DWORD dwDest)
{
    PMEMORYMODULE module = (PMEMORYMODULE) hModule;
    if (module->hAliasedModule) {
        return module->callbacks->systemGetModuleFileNameA(
            module->hAliasedModule, name, dwDest);
    }

    if (module->hOriginalModule) {
        return module->callbacks->systemGetModuleFileNameA(
            module->hOriginalModule, name, dwDest);
    }

    return 0xFFFFFFFF;
}

DWORD MemoryModuleFileNameW(HMODULE hModule, LPWSTR name, DWORD dwDest)
{
    PMEMORYMODULE module = (PMEMORYMODULE) hModule;
    if (module->hAliasedModule) {
        return module->callbacks->systemGetModuleFileNameW(
            module->hAliasedModule, name, dwDest);
    }

    if (module->hOriginalModule) {
        return module->callbacks->systemGetModuleFileNameW(
            module->hOriginalModule, name, dwDest);
    }

    return 0xFFFFFFFF;
}

void MemoryFreeLibrary(HMEMORYMODULE mod)
{
    PMEMORYMODULE module = (PMEMORYMODULE)mod;
    FUNCHASH *phIdx, *phTmp, *phExports;

    if (module == NULL) {
        return;
    }

    dprint("MemoryFreeLibrary (%p)\n", mod);

    phExports = module->phExportsIndex;

    if (module->initialized && module->pcDllEntry) {
        // notify library about detaching from process
        DllEntryProc DllEntry = (DllEntryProc) (module->codeBase + module->headers->OptionalHeader.AddressOfEntryPoint);
        (*DllEntry)((HINSTANCE)module->codeBase, DLL_PROCESS_DETACH, 0);
    }

    if (module->modules != NULL) {
        // free previously opened libraries
        int i;
        for (i=0; i<module->numModules; i++) {
            if (module->modules[i] != NULL) {
                module->callbacks->freeLibrary(module->modules[i]);
            }
        }

        free(module->modules);
    }

    if (module->codeBase != NULL) {
        // release memory of library
        VirtualFree(module->codeBase, 0, MEM_RELEASE);
    }

    free(module->exports.fpFunctions);

    HASH_ITER(hh, phExports, phIdx, phTmp) {
        HASH_DEL(phExports, phIdx);
        free(phIdx->name);
        free(phIdx);
    }

    HeapFree(GetProcessHeap(), 0, module);
}

#define DEFAULT_LANGUAGE MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL)

HMEMORYRSRC _MemoryFindResourceW(HMEMORYMODULE module, LPCWSTR name, LPCWSTR type)
{
    return _MemoryFindResourceExW(module, name, type, DEFAULT_LANGUAGE);
}

static PIMAGE_RESOURCE_DIRECTORY_ENTRY _MemorySearchResourceEntry(
    void *root,
    PIMAGE_RESOURCE_DIRECTORY resources,
    LPCWSTR key)
{
    PIMAGE_RESOURCE_DIRECTORY_ENTRY entries = (PIMAGE_RESOURCE_DIRECTORY_ENTRY) (
        resources + 1);
    PIMAGE_RESOURCE_DIRECTORY_ENTRY result = NULL;

    DWORD start;
    DWORD end;
    DWORD middle;

    if (!IS_INTRESOURCE(key) && key[0] == TEXT('#')) {
        // special case: resource id given as string
        TCHAR *endpos = NULL;
        long int tmpkey = (WORD) _tcstol((TCHAR *) &key[1], &endpos, 10);
        if (tmpkey <= 0xffff && lstrlen(endpos) == 0) {
            key = MAKEINTRESOURCEW(tmpkey);
        }
    }

    // entries are stored as ordered list of named entries,
    // followed by an ordered list of id entries - we can do
    // a binary search to find faster...
    if (IS_INTRESOURCE(key)) {
        WORD check = (WORD) (uintptr_t) key;
        start = resources->NumberOfNamedEntries;
        end = start + resources->NumberOfIdEntries;

        while (end > start) {
            WORD entryName;
            middle = (start + end) >> 1;
            entryName = (WORD) entries[middle].Name;
            if (check < entryName) {
                end = (end != middle ? middle : middle-1);
            } else if (check > entryName) {
                start = (start != middle ? middle : middle+1);
            } else {
                result = &entries[middle];
                break;
            }
        }
    } else {
        LPCWSTR searchKey;
        size_t searchKeyLen = wcslen(key);
        searchKey = key;
        start = 0;
        end = resources->NumberOfNamedEntries;
        while (end > start) {
            int cmp;
            PIMAGE_RESOURCE_DIR_STRING_U resourceString;
            middle = (start + end) >> 1;
            resourceString = (PIMAGE_RESOURCE_DIR_STRING_U) OffsetPointer(root, entries[middle].Name & 0x7FFFFFFF);
            cmp = _wcsnicmp(searchKey, resourceString->NameString, resourceString->Length);
            if (cmp == 0) {
                // Handle partial match
                if (searchKeyLen > resourceString->Length) {
                    cmp = 1;
                } else if (searchKeyLen < resourceString->Length) {
                    cmp = -1;
                }
            }
            if (cmp < 0) {
                end = (middle != end ? middle : middle-1);
            } else if (cmp > 0) {
                start = (middle != start ? middle : middle+1);
            } else {
                result = &entries[middle];
                break;
            }
        }
    }

    return result;
}

HMEMORYRSRC _MemoryFindResourceExW(HMEMORYMODULE hModule, LPCWSTR name, LPCWSTR type, WORD language)
{
    PMEMORYMODULE module = (PMEMORYMODULE) hModule;
    PIMAGE_RESOURCE_DIRECTORY rootResources;
    PIMAGE_RESOURCE_DIRECTORY nameResources;
    PIMAGE_RESOURCE_DIRECTORY typeResources;
    PIMAGE_RESOURCE_DIRECTORY_ENTRY foundType;
    PIMAGE_RESOURCE_DIRECTORY_ENTRY foundName;
    PIMAGE_RESOURCE_DIRECTORY_ENTRY foundLanguage;

    if (!module->resources) {
        // no resource table found
        SetLastError(ERROR_RESOURCE_DATA_NOT_FOUND);
        return NULL;
    }

    if (language == DEFAULT_LANGUAGE) {
        // use language from current thread
        language = LANGIDFROMLCID(GetThreadLocale());
    }

    // resources are stored as three-level tree
    // - first node is the type
    // - second node is the name
    // - third node is the language
    rootResources = (PIMAGE_RESOURCE_DIRECTORY) module->resources;
    foundType = _MemorySearchResourceEntry(rootResources, rootResources, type);
    if (foundType == NULL) {
        SetLastError(ERROR_RESOURCE_TYPE_NOT_FOUND);
        return NULL;
    }

    typeResources = (PIMAGE_RESOURCE_DIRECTORY) (module->resources + (foundType->OffsetToData & 0x7fffffff));
    foundName = _MemorySearchResourceEntry(rootResources, typeResources, name);
    if (foundName == NULL) {
        SetLastError(ERROR_RESOURCE_NAME_NOT_FOUND);
        return NULL;
    }

    nameResources = (PIMAGE_RESOURCE_DIRECTORY) (module->resources + (foundName->OffsetToData & 0x7fffffff));
    foundLanguage = _MemorySearchResourceEntry(rootResources, nameResources, (LPCWSTR) (uintptr_t) language);
    if (foundLanguage == NULL) {
        // requested language not found, use first available
        if (nameResources->NumberOfIdEntries == 0) {
            SetLastError(ERROR_RESOURCE_LANG_NOT_FOUND);
            return NULL;
        }

        foundLanguage = (PIMAGE_RESOURCE_DIRECTORY_ENTRY) (nameResources + 1);
    }

    return (module->resources + (foundLanguage->OffsetToData & 0x7fffffff));
}

DWORD _MemorySizeofResource(HMEMORYMODULE module, HMEMORYRSRC resource)
{
    PIMAGE_RESOURCE_DATA_ENTRY entry;
    UNREFERENCED_PARAMETER(module);
    entry = (PIMAGE_RESOURCE_DATA_ENTRY) resource;
    if (entry == NULL) {
        return 0;
    }

    return entry->Size;
}

LPVOID _MemoryLoadResource(HMEMORYMODULE module, HMEMORYRSRC resource)
{
    unsigned char *codeBase = ((PMEMORYMODULE) module)->codeBase;
    PIMAGE_RESOURCE_DATA_ENTRY entry = (PIMAGE_RESOURCE_DATA_ENTRY) resource;
    if (entry == NULL) {
        return NULL;
    }

    return codeBase + entry->OffsetToData;
}

HMEMORYRSRC MemoryFindResourceA(HMEMORYMODULE module, LPCSTR name, LPCSTR type)
{
    return MemoryFindResourceExA(module, name, type, DEFAULT_LANGUAGE);
}


HMEMORYRSRC MemoryFindResourceW(HMEMORYMODULE module, LPCWSTR name, LPCWSTR type)
{
    return _MemoryFindResourceW(module, name, type);
}

HMEMORYRSRC MemoryFindResourceExA(HMEMORYMODULE hModule, LPCSTR name, LPCSTR type, WORD language)
{
    size_t namelen;
    size_t typelen;
    LPWSTR wName;
    LPWSTR wType;

    if (!name || !type)
        return NULL;

    namelen = (strlen(name) + 1) * 2;
    typelen = (strlen(type) + 1) * 2;
    wName = _alloca(namelen);
    wType = _alloca(typelen);
    mbstowcs(wName, name, namelen);
    mbstowcs(wType, type, typelen);

    return MemoryFindResourceW(hModule, wName, wType);
}

HMEMORYRSRC MemoryFindResourceExW(HMEMORYMODULE hModule, LPCWSTR name, LPCWSTR type, WORD language)
{
    PMEMORYMODULE module = (PMEMORYMODULE)hModule;
    HMEMORYRSRC resource = NULL;

    if (!hModule)
        return NULL;

    if (!resource && module->hAliasedModule) {
        resource = module->callbacks->systemFindResourceExW(
            module->hAliasedModule, name, type, language
        );
    }

    if (!resource && module->hOriginalModule) {
        resource = module->callbacks->systemFindResourceExW(
            module->hOriginalModule, name, type, language
        );
    }

    if (resource)
        return resource;

    return _MemoryFindResourceExW(hModule, name, type, language);
}

DWORD MemorySizeofResource(HMEMORYMODULE hModule, HMEMORYRSRC resource)
{
    PMEMORYMODULE module = (PMEMORYMODULE) hModule;
    DWORD dwSize = 0;

    if (!hModule)
        return 0;

    if (!dwSize && module->hAliasedModule) {
        dwSize = module->callbacks->systemSizeofResource(
            module->hAliasedModule, resource
        );
    }

    if (!dwSize && module->hOriginalModule) {
        dwSize = module->callbacks->systemSizeofResource(
            module->hOriginalModule, resource
        );
    }

    if (dwSize)
        return dwSize;

    return _MemorySizeofResource(hModule, resource);
}

LPVOID MemoryLoadResource(HMEMORYMODULE hModule, HMEMORYRSRC resource)
{
    PMEMORYMODULE module = (PMEMORYMODULE) hModule;
    PVOID *pvData = NULL;

    if (!hModule)
        return 0;

    if (!pvData && module->hAliasedModule) {
        pvData = module->callbacks->systemLoadResource(
            module->hAliasedModule, resource
        );
    }

    if (!pvData && module->hOriginalModule) {
        pvData = module->callbacks->systemLoadResource(
            module->hOriginalModule, resource
        );
    }

    if (pvData)
        return pvData;

    return _MemoryLoadResource(module, resource);
}
