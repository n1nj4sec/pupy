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

typedef BOOL (WINAPI *DllEntryProc)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);
typedef int (WINAPI *ExeEntryProc)(void);

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
    PIMAGE_NT_HEADERS headers;
    unsigned char *codeBase;
    HCUSTOMMODULE *modules;
    int numModules;
    BOOL initialized;
    BOOL isDLL;
    BOOL isRelocated;
    CustomFreeLibraryFunc freeLibrary;
    CustomGetProcAddress getProcAddress;
    CustomLoadLibraryW loadLibraryW;
    CustomLoadLibraryA loadLibraryA;
    CustomLoadLibraryExA loadLibraryExA;
    CustomLoadLibraryExW loadLibraryExW;
    CustomGetModuleHandleA getModuleHandleA;
    CustomGetModuleHandleW getModuleHandleW;
    ExeEntryProc exeEntry;
    DWORD pageSize;
    FUNCIDX exports;
    FUNCHASH *phExportsIndex;
    DllEntryProc pcDllEntry;
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
             (sectionData->size % module->pageSize) == 0)
           ) {
            // Only allowed to decommit whole pages
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

    PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY(module, IMAGE_DIRECTORY_ENTRY_TLS);
    if (directory->VirtualAddress == 0) {
        return TRUE;
    }

    tls = (PIMAGE_TLS_DIRECTORY) (codeBase + directory->VirtualAddress);
    callback = (PIMAGE_TLS_CALLBACK *) tls->AddressOfCallBacks;
    if (callback) {
        while (*callback) {
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

typedef struct {
    const char *symbol;
    FARPROC addr;
} ImportHooks;

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
BuildImportTable(PMEMORYMODULE module)
{
    unsigned char *codeBase = module->codeBase;
    PIMAGE_IMPORT_DESCRIPTOR importDesc;
    BOOL result = TRUE;

    PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY(
        module, IMAGE_DIRECTORY_ENTRY_IMPORT);

    ImportHooks kernel32Hooks[] = {
        {"LoadLibraryA", (FARPROC) module->loadLibraryA},
        {"LoadLibraryW", (FARPROC) module->loadLibraryW},
        {"LoadLibraryExA", (FARPROC) module->loadLibraryExA},
        {"LoadLibraryExW", (FARPROC) module->loadLibraryExW},
        {"GetModuleHandleA", (FARPROC) module->getModuleHandleA},
        {"GetModuleHandleW", (FARPROC) module->getModuleHandleW},
        {"GetProcAddress", (FARPROC) module->getProcAddress},
        {"FreeLibrary", (FARPROC) module->freeLibrary},
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

        dprint("Import %s (LoadLibraryA = %p)\n", lpcszLibraryName, module->loadLibraryA);

        handle = module->loadLibraryA(lpcszLibraryName);

        dprint("Import %s -> %p\n", lpcszLibraryName, handle);

        if (!handle) {
            SetLastError(ERROR_MOD_NOT_FOUND);
            result = FALSE;
            break;
        }

        tmp = (HCUSTOMMODULE *) realloc(
            module->modules, (module->numModules+1)*(sizeof(HCUSTOMMODULE)));
        if (tmp == NULL) {
            module->freeLibrary(handle);
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

        if (!_stricmp(lpcszLibraryName, "KERNEL32.DLL")) {
            hooks = kernel32Hooks;
            dprint("Use hooks for kernel32: %p\n", hooks);
        }

        dprint("Resolving symbols.. (%p)\n", thunkRef);

        for (; thunkRef && *thunkRef; thunkRef++, funcRef++) {
            dprint("Thunk value: %p\n", *thunkRef);

            if (IMAGE_SNAP_BY_ORDINAL(*thunkRef)) {

                dprint("Import by thunk (%d)\n", IMAGE_ORDINAL(*thunkRef));

                *funcRef = module->getProcAddress(
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
                    hooks, module->getProcAddress,
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
            module->freeLibrary(handle);
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

HMEMORYMODULE MemoryLoadLibraryEx(
    const void *data,
    PDL_CALLBACKS callbacks,
    void *dllmainArg,
    BOOL blExecuteCallbacks)
{
    PMEMORYMODULE result;
    PIMAGE_DOS_HEADER dos_header;
    PIMAGE_NT_HEADERS old_header;
    unsigned char *code, *headers;
    SIZE_T locationDelta;
    SYSTEM_INFO sysInfo;
    HMODULE hModule;

    dprint("MemoryLoadLibraryEx: Load from %p\n", data);

    dos_header = (PIMAGE_DOS_HEADER)data;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return NULL;
    }

    old_header = (PIMAGE_NT_HEADERS)&((const unsigned char *)(data))[dos_header->e_lfanew];
    if (old_header->Signature != IMAGE_NT_SIGNATURE) {
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return NULL;
    }

#ifdef _WIN64
    if (old_header->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
#else
    if (old_header->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
#endif
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return NULL;
    }

    if (old_header->OptionalHeader.SectionAlignment & 1) {
        // Only support section alignments that are a multiple of 2
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return NULL;
    }

    // reserve memory for image of library
    // XXX: is it correct to commit the complete memory region at once?
    //      calling DllEntry raises an exception if we don't...
    code = (unsigned char *)VirtualAlloc((LPVOID)(old_header->OptionalHeader.ImageBase),
        old_header->OptionalHeader.SizeOfImage,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE);

    if (code == NULL) {
        // try to allocate memory at arbitrary position
        code = (unsigned char *)VirtualAlloc(NULL,
            old_header->OptionalHeader.SizeOfImage,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE);
        if (code == NULL) {
            SetLastError(ERROR_OUTOFMEMORY);
            return NULL;
        }
    }

    dprint("ImageBase: %p\n", code);

    result = (PMEMORYMODULE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(MEMORYMODULE));
    if (result == NULL) {
        VirtualFree(code, 0, MEM_RELEASE);
        SetLastError(ERROR_OUTOFMEMORY);
        return NULL;
    }

    result->codeBase = code;
    result->isDLL = (old_header->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;

    result->loadLibraryA = callbacks->loadLibraryA;
    result->loadLibraryW = callbacks->loadLibraryW;
    result->loadLibraryExA = callbacks->loadLibraryExA;
    result->loadLibraryExW = callbacks->loadLibraryExW;
    result->getModuleHandleA = callbacks->getModuleHandleA;
    result->getModuleHandleW = callbacks->getModuleHandleW;
    result->getProcAddress = callbacks->getProcAddress;
    result->freeLibrary = callbacks->freeLibrary;

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
    dprint("Execute TLS..\n");
    if (!ExecuteTLS(result)) {
        goto error;
    }

#ifdef _WIN64
    // Enable exceptions
    dprint("Register Exception table..\n");
    if (!RegisterExceptionTable(result)) {
        goto error;
    }
#endif

    // Build functions table
    dprint("Build export table..\n");
    BuildExportTable(result);

    // get entry point of loaded library
    if (blExecuteCallbacks && result->isDLL && result->pcDllEntry) {
        BOOL successfull;

        dprint(
            "Execute EP (ImageBase: %p EP: %p ARG: %p)..\n",
            code, result->pcDllEntry, dllmainArg
        );

        // notify library about attaching to process
        successfull = result->pcDllEntry(
            (HINSTANCE)code, DLL_PROCESS_ATTACH, dllmainArg);

        if (!successfull) {
            SetLastError(ERROR_DLL_INIT_FAILED);
            goto error;
        }
        result->initialized = TRUE;
    }

    dprint("MemoryLoadLibraryEx: Library loaded\n");

    // Cleanup PE headers
    CleanupHeaders(result);

    dprint("MemoryLoadLibraryEx: headers cleaned up\n");

    return (HMEMORYMODULE)result;

error:
    dprint("MemoryLoadLibraryEx: error\n");
    // cleanup
    MemoryFreeLibrary(result);
    return NULL;
}

FARPROC MemoryGetProcAddress(HMEMORYMODULE hmodule, LPCSTR name)
{
    PMEMORYMODULE module = (PMEMORYMODULE) hmodule;
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

void MemoryFreeLibrary(HMEMORYMODULE mod)
{
    PMEMORYMODULE module = (PMEMORYMODULE)mod;
    FUNCHASH *phIdx, *phTmp, *phExports;

    if (module == NULL) {
        return;
    }

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
                module->freeLibrary(module->modules[i]);
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
