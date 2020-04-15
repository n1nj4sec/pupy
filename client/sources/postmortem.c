#include <Shlobj.h>
#include <stdio.h>

#define PYTHON_DYNLOAD_OS_NO_BLOBS

#include "postmortem.h"
#include "debug.h"

#include "MyLoadLibrary.h"

#include "Python-stacktrace.h"
#include "Python-stacktrace.c"

#define ECODE(x) EXCEPTION_ ## x, # x

typedef BOOL (WINAPI *tGetPolicy)(LPDWORD lpFlags);
typedef BOOL (WINAPI *tSetPolicy)(DWORD dwFlags);

typedef struct _EXCMSG {
  DWORD dwExceptionCode;
  LPCSTR pszExceptionHuman;
} EXCMSG, *PEXCMSG;

static
LPCSTR code2str(DWORD dwExceptionCode) {
  size_t i;
  static const EXCMSG messages[] = {
    ECODE(ACCESS_VIOLATION),
    ECODE(ARRAY_BOUNDS_EXCEEDED),
    ECODE(BREAKPOINT),
    ECODE(DATATYPE_MISALIGNMENT),
    ECODE(FLT_DENORMAL_OPERAND),
    ECODE(FLT_DIVIDE_BY_ZERO),
    ECODE(FLT_INEXACT_RESULT),
    ECODE(FLT_INVALID_OPERATION),
    ECODE(FLT_OVERFLOW),
    ECODE(FLT_STACK_CHECK),
    ECODE(FLT_UNDERFLOW),
    ECODE(ILLEGAL_INSTRUCTION),
    ECODE(IN_PAGE_ERROR),
    ECODE(INT_DIVIDE_BY_ZERO),
    ECODE(INT_OVERFLOW),
    ECODE(INVALID_DISPOSITION),
    ECODE(NONCONTINUABLE_EXCEPTION),
    ECODE(PRIV_INSTRUCTION),
    ECODE(SINGLE_STEP),
    ECODE(STACK_OVERFLOW),
  };

  for (i = 0; i<sizeof(messages) / sizeof(EXCMSG); i++) {
    if (dwExceptionCode == messages[i].dwExceptionCode)
      return messages[i].pszExceptionHuman;
  }

  return "UNKNOWN";
}

typedef HRESULT (WINAPI *SHGetFolderPathAndSubDirW_t)(
  HWND   hwnd,
  int    csidl,
  HANDLE hToken,
  DWORD  dwFlags,
  LPCWSTR pszSubDir,
  LPWSTR pszPath
);

typedef DWORD (WINAPI *SymSetOptions_t)(
  DWORD SymOptions
);

typedef BOOL (WINAPI *SymInitialize_t)(
  HANDLE hProcess,
  PCSTR  UserSearchPath,
  BOOL   fInvadeProcess
);

typedef PVOID (WINAPI *SymFunctionTableAccess_t)(
  HANDLE hProcess,
  DWORD  AddrBase
);

typedef DWORD (WINAPI *SymGetModuleBase_t)(
  HANDLE hProcess,
  DWORD  dwAddr
);

typedef DWORD64 (WINAPI *SymGetModuleBase64_t)(
  HANDLE hProcess,
  DWORD64  dwAddr
);

typedef BOOL (WINAPI *SymGetSymFromAddr_t)(
  HANDLE           hProcess,
  DWORD            dwAddr,
  PDWORD           pdwDisplacement,
  PIMAGEHLP_SYMBOL Symbol
);

typedef BOOL (WINAPI *SymGetSymFromAddr64_t)(
  HANDLE             hProcess,
  DWORD64            qwAddr,
  PDWORD64           pdwDisplacement,
  PIMAGEHLP_SYMBOL64 Symbol
);

typedef BOOL (WINAPI *StackWalk_t)(
  DWORD  MachineType,
  HANDLE hProcess,
  HANDLE hThread,
  PVOID  StackFrame,
  PVOID  ContextRecord,
  PVOID  ReadMemoryRoutine,
  PVOID  FunctionTableAccessRoutine,
  PVOID  GetModuleBaseRoutine,
  PVOID  TranslateAddress
);

typedef BOOL (WINAPI *EnumProcessModules_t)(
  HANDLE  hProcess,
  HMODULE *lphModule,
  DWORD   cb,
  LPDWORD lpcbNeeded
);

#ifdef DEBUG
static
void CreateMiniDump(HMODULE hDbgHelp, LPCWSTR pwzFolder, EXCEPTION_POINTERS* pExceptionPointers) {
    BOOL blDumpCreated = FALSE;
    HANDLE hDumpFile = INVALID_HANDLE_VALUE;
    HANDLE hCurrentProcess = GetCurrentProcess();
    DWORD dwCurrentProcessId = GetCurrentProcessId();

    WCHAR minidump_path[MAX_PATH] = L"\0";

    MINIDUMP_EXCEPTION_INFORMATION mdei;

    MiniDumpWriteDump_t pMiniDumpWriteDump = (MiniDumpWriteDump_t) GetProcAddress(
      hDbgHelp, "MiniDumpWriteDump"
    );

    if (!pMiniDumpWriteDump) {
      dprint("Failed to find pMiniDumpWriteDump\n");
      return;
    }

    _snwprintf(
      minidump_path, sizeof(minidump_path) - 1,
      L"%s\\tmp_dump_%d.bin", pwzFolder, GetCurrentProcessId()
    );

    hDumpFile = CreateFileW(
      minidump_path,
      GENERIC_READ | GENERIC_WRITE,
      0, NULL,
      CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
      NULL
    );

    if (hDumpFile == NULL || hDumpFile == INVALID_HANDLE_VALUE) {
      dprint("Failed to create minidump file\n");
      return;
    }

    mdei.ThreadId           = GetCurrentThreadId();
    mdei.ExceptionPointers  = pExceptionPointers;
    mdei.ClientPointers     = FALSE;

    dprint(
      "HANDLE: %p PID: %08x HFILE: %p TYPE: %d\n",
        hCurrentProcess,
        dwCurrentProcessId,
        hDumpFile, MiniDumpNormal
    );

    if (pExceptionPointers) {
      dprint(
        "Using ExceptionPointers (PTR=%p) MDEI=%p TID=%08x\n",
        mdei.ExceptionPointers, &mdei, mdei.ThreadId
      );
    }

    blDumpCreated = pMiniDumpWriteDump(
      hCurrentProcess,
      dwCurrentProcessId,
      hDumpFile, MiniDumpWithFullMemory,
      pExceptionPointers? (&mdei) : NULL,
      NULL,
      NULL
    );

    CloseHandle(hDumpFile);

    if (blDumpCreated)
        dprint("Global crash handler completed successfully\n");
    else
      dprint("Global crash handler failed to create dump\n");
}
#endif

static
BOOL SaveLibraryInfo(PVOID pvCallbackData, LPCSTR pszName, PVOID pvBaseImage, ULONG ulSize)
{
    HANDLE hExceptionInfoFile = (HANDLE) pvCallbackData;
    CHAR module_info_buf[8192] = "\0";
    DWORD dwWritten;
    int module_info_buf_size;

    dprint(
      "SaveLibraryInfo called (%p, \"%s\", %p, %u)\n",
      pvCallbackData, pszName, pvBaseImage, ulSize
    );

    module_info_buf_size = snprintf(
      module_info_buf, sizeof(module_info_buf)-1, "%p - %p\t%s\n",
      pvBaseImage, (((UINT_PTR) pvBaseImage) + ulSize), pszName
    );

    dprint("+ %s", module_info_buf);

    if (module_info_buf_size > 0)
      return WriteFile(
          hExceptionInfoFile, module_info_buf, module_info_buf_size, &dwWritten, NULL
      );

    return FALSE;
}

static
void SavePythonStackTrace(
    PVOID pvCallbackData, LPCSTR pszFunction, LPCSTR pszFile, DWORD dwLine)
{
  CHAR buffer[8192];
  DWORD dwWritten;
  int buffer_len;
  HANDLE hExceptionInfoFile = (HANDLE) pvCallbackData;

  if (pszFile == NULL) {
    buffer_len = snprintf(
      buffer, sizeof(buffer)-1,
      "\n%s [%d]\n",
      pszFunction, dwLine
    );
  } else {
    dprint("Python stack: %s %s:%d\n", pszFunction, pszFile, dwLine);

    buffer_len = snprintf(
      buffer, sizeof(buffer)-1, "+ %s\t%s:%d\n",
      pszFunction, pszFile, dwLine
    );
  }

  if (buffer_len > 0)
    WriteFile(
      hExceptionInfoFile,
      buffer, buffer_len, &dwWritten, NULL
    );
}

#ifdef _WIN64
static
PVOID WINAPI PupyFunctionTableAccess(HANDLE  hProcess, DWORD64 AddrBase) {
  // hProcess - Ignoree
  DWORD64 ImageBase;
  return RtlLookupFunctionEntry((PVOID) AddrBase, &ImageBase, NULL);
}
#endif

static
#ifdef _WIN64
DWORD64 WINAPI PupyGetModuleBase(HANDLE  hProcess, DWORD64 pvAddr)
#else
DWORD WINAPI PupyGetModuleBase(HANDLE  hProcess, DWORD pvAddr)
#endif
{
  // hProcess - Ignoree
  PVOID pvModuleBase = NULL;
  if (MyFindMemoryModuleNameByAddr(pvAddr, NULL, &pvModuleBase, NULL))
    return pvModuleBase;
  else if (GetModuleHandleExA(
    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,(LPCSTR) pvAddr, &pvModuleBase))
      return pvModuleBase;
  else
    return 0;
}


static
VOID SaveContextStack(HMODULE hDbgHelp, HANDLE hExceptionInfoFile, PCONTEXT pContext)
{
    BOOL                result;
    BOOL                blSymbolFound;
    HANDLE              process;
    HANDLE              thread;
    ULONG               frame;
    DWORD               dwWritten;
    CHAR                buffer[1024];
    int                 buffer_len;

#ifdef _WIN64
    STACKFRAME64              stack;
    IMAGEHLP_SYMBOL_STORAGE64 symbol_storage;
    PIMAGEHLP_SYMBOL64        symbol = &(symbol_storage.symbol);
    DWORD64                   displacement;

    SymSetOptions_t pSymSetOptions = (SymSetOptions_t)
      GetProcAddress(hDbgHelp, "SymSetOptions");

    SymInitialize_t pSymInitialize = (SymInitialize_t)
      GetProcAddress(hDbgHelp, "SymInitialize");

    SymGetSymFromAddr64_t pSymGetSymFromAddr64 = (SymGetSymFromAddr64_t)
      GetProcAddress(hDbgHelp, "SymGetSymFromAddr64");

    StackWalk_t pStackWalk = (StackWalk_t)
      GetProcAddress(hDbgHelp, "StackWalk64");

    if (! (pSymGetSymFromAddr64 && pStackWalk)) {
      dprint("Not all functions find at dbghelp\n");
      return;
    }

#else
    STACKFRAME              stack;
    IMAGEHLP_SYMBOL_STORAGE symbol_storage;
    PIMAGEHLP_SYMBOL        symbol = &(symbol_storage.symbol);
    DWORD                   displacement;

    SymSetOptions_t pSymSetOptions = (SymSetOptions_t)
      GetProcAddress(hDbgHelp, "SymSetOptions");

    SymInitialize_t pSymInitialize = (SymInitialize_t)
      GetProcAddress(hDbgHelp, "SymInitialize");

    SymFunctionTableAccess_t pSymFunctionTableAccess = (SymFunctionTableAccess_t)
      GetProcAddress(hDbgHelp, "SymFunctionTableAccess");

    SymGetSymFromAddr_t pSymGetSymFromAddr = (SymGetSymFromAddr_t)
      GetProcAddress(hDbgHelp, "SymGetSymFromAddr");

    StackWalk_t pStackWalk = (StackWalk_t)
      GetProcAddress(hDbgHelp, "StackWalk");

    if (! (pSymFunctionTableAccess && pSymGetSymFromAddr && pStackWalk)) {
      dprint("Not all functions find at dbghelp\n");
      return;
    }
#endif

    if (!pContext) {
      dprint("pContext is NULL\n");
      return;
    }

    pSymSetOptions(
      SYMOPT_NO_PROMPTS | SYMOPT_NO_IMAGE_SEARCH | SYMOPT_IGNORE_NT_SYMPATH | \
        SYMOPT_DISABLE_SYMSRV_AUTODETECT | SYMOPT_DEFERRED_LOADS
    );

    pSymInitialize(
      GetCurrentProcess(), NULL, TRUE
    );

    memset(&stack, 0, sizeof(stack));

    process                = GetCurrentProcess();
    thread                 = GetCurrentThread();
    displacement           = 0;
    stack.AddrPC.Mode      = AddrModeFlat;
    stack.AddrStack.Mode   = AddrModeFlat;
    stack.AddrFrame.Mode   = AddrModeFlat;

#ifdef _WIN64
    stack.AddrPC.Offset    = pContext->Rip;
    stack.AddrStack.Offset = pContext->Rsp;
    stack.AddrFrame.Offset = pContext->Rbp;
#else
    stack.AddrPC.Offset    = pContext->Eip;
    stack.AddrStack.Offset = pContext->Esp;
    stack.AddrFrame.Offset = pContext->Ebp;
#endif

    for( frame = 0; frame < 64; frame++ ) {
        LPCSTR pcModuleName = NULL;
        PVOID pcModuleBase = NULL;

        symbol->SizeOfStruct  = sizeof(symbol_storage.symbol);
        symbol->MaxNameLength = sizeof(symbol_storage) -
            sizeof(symbol_storage.symbol);

        blSymbolFound = False;

#ifdef _WIN64
        result = pStackWalk(
            IMAGE_FILE_MACHINE_AMD64,
            process,
            thread,
            &stack,
            pContext,
            NULL,
            PupyFunctionTableAccess,
            PupyGetModuleBase,
            NULL
        );

        pSymGetSymFromAddr64(
            process, (ULONG64) stack.AddrPC.Offset, &displacement, symbol
        );

#else
        result = pStackWalk(
            IMAGE_FILE_MACHINE_I386,
            process,
            thread,
            &stack,
            pContext,
            NULL,
            pSymFunctionTableAccess,
            PupyGetModuleBase,
            NULL
        );

        pSymGetSymFromAddr(
            process, (ULONG) stack.AddrPC.Offset, &displacement, symbol
        );

#endif
        if (blSymbolFound) {
          buffer_len = snprintf(
              buffer,
              sizeof(buffer) - 1,
              "+ %lu:\tSYS:%s\t(PC %p)\n",
              frame,
              symbol->Name,
              stack.AddrPC.Offset
          );
        } else {
          LPCSTR pcModuleName = NULL;
          PVOID pcModuleBase = NULL;

          if (MyFindMemoryModuleNameByAddr(
                stack.AddrPC.Offset, &pcModuleName, &pcModuleBase, NULL)) {
              buffer_len = snprintf(
                buffer,
                sizeof(buffer) - 1,
                "+ %lu:\t[PC %p]\tMEM:%s+0x%x\n",
                frame,
                stack.AddrPC.Offset,
                pcModuleName,
                ((UINT_PTR)stack.AddrPC.Offset) - ((UINT_PTR)pcModuleBase)
            );
          } else {
            HMODULE hSymbolModule;
            CHAR szModName[MAX_PATH];
            PCHAR pcModName = szModName;
            BOOL blFound = GetModuleHandleExA(
              GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
              (LPCSTR) stack.AddrPC.Offset,
              &hSymbolModule
            );

            if (blFound && GetModuleFileNameA(
                hSymbolModule, szModName, sizeof(szModName))) {

              PCHAR pcLastDm = strrchr(szModName, '\\');
              if (pcLastDm)
                pcModName = pcLastDm + 1;

              buffer_len = snprintf(
                  buffer,
                  sizeof(buffer) - 1,
                  "+ %lu:\t[PC %p]\tSYS:%s+0x%x\n",
                  frame, stack.AddrPC.Offset,
                  pcModName,
                  ((UINT_PTR)stack.AddrPC.Offset) - ((UINT_PTR)hSymbolModule)
              );
            } else {
              buffer_len = snprintf(
                  buffer,
                  sizeof(buffer) - 1,
                  "+ %lu:\t[PC %p]\t?\t\t\n",
                  frame,
                  stack.AddrPC.Offset
              );
            }
          }
        }

        if (buffer_len > 0)
          WriteFile(hExceptionInfoFile, buffer, buffer_len, &dwWritten, NULL);

        if( !result )
            break;
    }
}

#ifdef _WIN64
static
USHORT GetBackTrace(USHORT usFrames, PVOID* BackTrace)
{
    USHORT usFrame;
    CONTEXT ContextRecord;
    RtlCaptureContext(&ContextRecord);

    dprint("GetBackTrace: Start for %p\n", ContextRecord.Rip);

    for (usFrame = 0; usFrame < usFrames; usFrame++)
    {
        DWORD64 ImageBase;
        PVOID HandlerData;
        DWORD64 EstablisherFrame;

        PRUNTIME_FUNCTION pFunctionEntry = RtlLookupFunctionEntry(
          ContextRecord.Rip, &ImageBase, NULL
        );

        if (pFunctionEntry == NULL) {
            dprint("GetBackTrace: Break on %p\n", ContextRecord.Rip);
            break;
        }

        RtlVirtualUnwind(
          0,
          ImageBase,
          ContextRecord.Rip,
          pFunctionEntry,
          &ContextRecord,
          &HandlerData,
          &EstablisherFrame,
          NULL
        );

        BackTrace[usFrame] = (PVOID)ContextRecord.Rip;
    }

    return usFrame;
}
#endif

static
VOID SaveCallingStack(HANDLE hExceptionInfoFile)
{
    PVOID pvFrames[MAX_STACK_FRAMES];
    PVOID pvModuleBase;
    LPCSTR pcModuleName;
    USHORT usFrames = 0;
    USHORT usFrame;
    DWORD dwWritten;

    char buffer[1024];
    int buffer_len;

#ifdef _WIN64
    usFrames = GetBackTrace(
      MAX_STACK_FRAMES, pvFrames
    );
#else
    usFrames = CaptureStackBackTrace(
      0, MAX_STACK_FRAMES, pvFrames, NULL
    );
#endif

    for(usFrame = 0; usFrame < usFrames; usFrame ++) {

      if (MyFindMemoryModuleNameByAddr(
            pvFrames[usFrame], &pcModuleName, &pvModuleBase, NULL)) {
          buffer_len = snprintf(
            buffer,
            sizeof(buffer) - 1,
            "+ %u:\t[PC %p]\tMEM:%s+0x%x\n",
            usFrame,
            pvFrames[usFrame],
            pcModuleName,
            ((UINT_PTR) pvFrames[usFrame]) - ((UINT_PTR) pvModuleBase)
        );
      } else {
        HMODULE hSymbolModule;
        CHAR szModName[MAX_PATH];
        PCHAR pcModName = szModName;
        BOOL blFound = GetModuleHandleExA(
          GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
          (LPCSTR) pvFrames[usFrame],
          &hSymbolModule
        );

        if (blFound && GetModuleFileNameA(
            hSymbolModule, szModName, sizeof(szModName))) {

          PCHAR pcLastDm = strrchr(szModName, '\\');
          if (pcLastDm)
            pcModName = pcLastDm + 1;

          buffer_len = snprintf(
              buffer,
              sizeof(buffer) - 1,
              "+ %lu:\t[PC %p]\tSYS:%s+0x%x\n",
              usFrame, pvFrames[usFrame],
              pcModName,
              ((UINT_PTR)pvFrames[usFrame]) - ((UINT_PTR)hSymbolModule)
          );
        } else {
          buffer_len = snprintf(
              buffer,
              sizeof(buffer) - 1,
              "+ %lu:\t[PC %p]\t?\t\t\n",
              usFrame,
              pvFrames[usFrame]
          );
        }
      }

      if (buffer_len > 0)
        WriteFile(hExceptionInfoFile, buffer, buffer_len, &dwWritten, NULL);
    }
}

static
VOID WriteToFile(HANDLE hFile, LPCSTR lpcstr)
{
  DWORD dwWritten;
  WriteFile(hFile, lpcstr, strlen(lpcstr), &dwWritten, NULL);
}

static
VOID MyEnumerateLoadedLibraries(HANDLE hExceptionInfoFile)
{
  HMODULE hMods[1024];
  DWORD cbNeeded;
  DWORD dwWritten;
  unsigned int i;
  HANDLE hCurrentProcess = GetCurrentProcess();
  HANDLE hPsapi = LoadLibraryA("PSAPI.DLL");
  EnumProcessModules_t pEnumProcessModules = (EnumProcessModules_t)
    GetProcAddress(hPsapi, "EnumProcessModules");

  if (!pEnumProcessModules) {
    dprint("Couldn't find pEnumProcessModules\n");
    return;
  }

  if (!pEnumProcessModules(hCurrentProcess, hMods, sizeof(hMods), &cbNeeded)) {
    dprint("EnumProcessModules failed\n");
    return;
  }

  for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
      CHAR szModName[MAX_PATH];
      CHAR dll_info[MAX_PATH];
      int dll_info_len;

      memset(dll_info, 0x0, sizeof(dll_info));
      memset(szModName, 0x0, sizeof(dll_info));

      if (!GetModuleFileNameA(hMods[i], szModName, sizeof(szModName)))
        continue;

      dll_info_len = snprintf(
        dll_info, sizeof(dll_info) - 1,
        "+ %p\t%s\n", hMods[i], szModName
      );

      dprint(dll_info);

      if (dll_info_len > 0)
        WriteFile(hExceptionInfoFile, dll_info, dll_info_len, &dwWritten, NULL);
  }

  dprint("DLLs enumeration completed\n");
}

static
void SaveExceptionInfo(
    HMODULE hDbgHelp, LPCWSTR pwzFolder,
      EXCEPTION_POINTERS* pExceptionPointers) {

    HANDLE hExceptionInfoFile = INVALID_HANDLE_VALUE;
    WCHAR einfo_path[MAX_PATH];
    CHAR einfo_buf[8192];
    DWORD dwWritten;

    int einfo_buf_size;
    int pystack_saved;

    dprint("SaveExceptionInfo start..\n");

    if (!(pExceptionPointers && pExceptionPointers->ExceptionRecord
            && pExceptionPointers->ContextRecord)) {
      dprint("No exception info!\n");
    }

    _snwprintf(
      einfo_path, (sizeof(einfo_path) / 2) - 1,
      L"%s\\tmp_dump_%d.einfo", pwzFolder, GetCurrentProcessId()
    );

    dwprint(L"File with exception info: %s\n", einfo_path);

    hExceptionInfoFile = CreateFileW(
      einfo_path,
      FILE_APPEND_DATA,
      0, NULL,
      OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL,
      NULL
    );

    if (hExceptionInfoFile == NULL || hExceptionInfoFile == INVALID_HANDLE_VALUE) {
      dprint("Failed to create exception info file\n");
      return;
    }

    if (pExceptionPointers) {
      einfo_buf_size = snprintf(
        einfo_buf, sizeof(einfo_buf) - 1,
        "\nCatch fatal exception: Code: %08x (%s)\n"
        "Flags: %08x Address: %p\n"
        "Registers:\n"

#ifdef _WIN64
        "RSP: %016x RBP: %016x RIP: %016x\n"
        "RAX: %016x RBX: %016x RCX: %016x RDX: %016x\n"
        "RSI: %016x RDI: %016x R8:  %016x R9:  %016x\n"
        "R10: %016x R11: %016x R12: %016x R13: %016x\n"
        "R14: %016x R15: %016x\n",
#else
        "ESP: %08x EBP: %08x EIP: %08x\n"
        "EAX: %08x EBX: %08x ECX: %08x EDX: %08x\n"
        "ESI: %08x EDI: %08x\n",
#endif

        pExceptionPointers->ExceptionRecord->ExceptionCode,
        code2str(pExceptionPointers->ExceptionRecord->ExceptionCode),
        pExceptionPointers->ExceptionRecord->ExceptionFlags,
        pExceptionPointers->ExceptionRecord->ExceptionAddress,

#ifdef _WIN64
        pExceptionPointers->ContextRecord->Rsp,
        pExceptionPointers->ContextRecord->Rbp,
        pExceptionPointers->ContextRecord->Rip,
        pExceptionPointers->ContextRecord->Rax,
        pExceptionPointers->ContextRecord->Rbx,
        pExceptionPointers->ContextRecord->Rcx,
        pExceptionPointers->ContextRecord->Rdx,
        pExceptionPointers->ContextRecord->Rsi,
        pExceptionPointers->ContextRecord->Rdi,
        pExceptionPointers->ContextRecord->R8,
        pExceptionPointers->ContextRecord->R9,
        pExceptionPointers->ContextRecord->R10,
        pExceptionPointers->ContextRecord->R11,
        pExceptionPointers->ContextRecord->R12,
        pExceptionPointers->ContextRecord->R13,
        pExceptionPointers->ContextRecord->R14,
        pExceptionPointers->ContextRecord->R15
#else
        pExceptionPointers->ContextRecord->Esp,
        pExceptionPointers->ContextRecord->Ebp,
        pExceptionPointers->ContextRecord->Eip,
        pExceptionPointers->ContextRecord->Eax,
        pExceptionPointers->ContextRecord->Ebx,
        pExceptionPointers->ContextRecord->Ecx,
        pExceptionPointers->ContextRecord->Edx,
        pExceptionPointers->ContextRecord->Esi,
        pExceptionPointers->ContextRecord->Edi
#endif
      );

      if (einfo_buf_size > 0)
        WriteFile(
          hExceptionInfoFile, einfo_buf, einfo_buf_size, &dwWritten, NULL
        );
    } else {
        static const char no_exception_header[] = "\nNon-exception crash report\n";
        DWORD dwWritten = 0;

        WriteFile(
          hExceptionInfoFile, no_exception_header, sizeof(no_exception_header)-1,
          &dwWritten, NULL
        );
    }

    dprint("Enumerating libraries..\n");
    WriteToFile(hExceptionInfoFile, "\nMemory modules:\n");
    MyEnumerateLibraries(SaveLibraryInfo, (PVOID) hExceptionInfoFile);

    WriteToFile(hExceptionInfoFile, "\nNormal modules:\n");
    MyEnumerateLoadedLibraries(hExceptionInfoFile);

    dprint("Generating stack trace ..\n");

    if (pExceptionPointers) {
      if (hDbgHelp) {
        WriteToFile(hExceptionInfoFile, "\nException Stack trace:\n");
        SaveContextStack(
          hDbgHelp, hExceptionInfoFile, pExceptionPointers->ContextRecord
        );
      } else {
        WriteToFile(
          hExceptionInfoFile,
          "\nFailed to save Exception Stack trace: DBGHELP not found\n"
        );
      }
    } else {
      WriteToFile(hExceptionInfoFile, "\nCurrent stack trace:\n");
      SaveCallingStack(hExceptionInfoFile);
    }

    dprint("Try to save python stack\n");
    WriteToFile(hExceptionInfoFile, "\nCurrent Python stacks (if any):\n");

    pystack_saved = Py_GetCurrentThreadStackTrace(
      SavePythonStackTrace, (PVOID) hExceptionInfoFile
    );

    dprint("Exception info saved (python=%d)\n", pystack_saved);
    CloseHandle(hExceptionInfoFile);
}

LONG WINAPI Postmortem(PEXCEPTION_POINTERS pExceptionPointers)
{
  WCHAR appdata_local[MAX_PATH];
  HMODULE hShell32 = LoadLibraryA("SHELL32.DLL");
  HMODULE hDbgHelp = LoadLibraryA("DBGHELP.DLL");

  SHGetFolderPathAndSubDirW_t pSHGetFolderPathAndSubDirW = NULL;

  if (pExceptionPointers && pExceptionPointers->ExceptionRecord) {
    dprint(
      "Catch fatal exception: Code: %08x (%s) Flags: %08x Address: %p\n",
      pExceptionPointers->ExceptionRecord->ExceptionCode,
      code2str(pExceptionPointers->ExceptionRecord->ExceptionCode),
      pExceptionPointers->ExceptionRecord->ExceptionFlags,
      pExceptionPointers->ExceptionRecord->ExceptionAddress
    );
  } else {
      dprint("Non-exception postmortem call\n");
      pExceptionPointers = NULL;
  }

  if (hShell32)
    pSHGetFolderPathAndSubDirW = (SHGetFolderPathAndSubDirW_t) GetProcAddress(
        hShell32, "SHGetFolderPathAndSubDirW");

  if (!pSHGetFolderPathAndSubDirW) {
    dprint("Failed to find SHGetFolderPathAndSubDirW (SHELL32.DLL AT %p)\n", hShell32);
    if (GetTempPathW(sizeof(appdata_local)/sizeof(WCHAR), appdata_local) < 1)
      return EXCEPTION_CONTINUE_SEARCH;
  }

  dprint("Creating folder for exception info\n");

  if (!SUCCEEDED(pSHGetFolderPathAndSubDirW(
          NULL, CSIDL_LOCAL_APPDATA | CSIDL_FLAG_CREATE, NULL,
          0, POSTMORTEM_DEST_FOLDER, appdata_local)))
  {
      dprint("Failed to create exception info folder\n");
      return EXCEPTION_CONTINUE_SEARCH;
  }

  dwprint(L"Folder created: %s\n", appdata_local);

  dprint("Generating crash context info..\n");
  SaveExceptionInfo(hDbgHelp, appdata_local, pExceptionPointers);
  dprint("Crash context saved\n");

#ifdef DEBUG
  if (pExceptionPointers) {
    if (hDbgHelp) {
      dprint("Generating minidump...\n");
      CreateMiniDump(hDbgHelp, appdata_local, pExceptionPointers);
    } else {
      dprint("Failed to load DBGHELP\n");
    }
  }
#endif

  dprint("Postmortem exception filter completed\n");
  return EXCEPTION_CONTINUE_SEARCH;
}

void EnableCrashingOnCrashes()
{
  static const DWORD EXCEPTION_SWALLOWING = 0x1;

  const HMODULE kernel32 = LoadLibraryA("kernel32.dll");

  const tGetPolicy pGetPolicy = (tGetPolicy) GetProcAddress(
    kernel32, "GetProcessUserModeExceptionPolicy");

  const tSetPolicy pSetPolicy = (tSetPolicy) GetProcAddress(
    kernel32, "SetProcessUserModeExceptionPolicy");

  if(pGetPolicy && pSetPolicy) {
    DWORD dwFlags = 0;
    dprint("EnableCrashingOnCrashes: ProcessUserModeExceptionPolicy found\n");
    if(pGetPolicy(&dwFlags)) {
      dprint("EnableCrashingOnCrashes: default policy: %08x\n", dwFlags);
      pSetPolicy(dwFlags & ~EXCEPTION_SWALLOWING);
    }
  }
}
