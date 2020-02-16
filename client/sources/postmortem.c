#include <Shlobj.h>

#include "postmortem.h"
#include "debug.h"

typedef HRESULT (*SHGetFolderPathAndSubDirA_t)(
  HWND   hwnd,
  int    csidl,
  HANDLE hToken,
  DWORD  dwFlags,
  LPCSTR pszSubDir,
  LPSTR  pszPath
);

void CreateMiniDump(EXCEPTION_POINTERS* pExceptionPointers) {
    BOOL blDumpCreated = FALSE;
    HANDLE hDumpFile = INVALID_HANDLE_VALUE;
    HANDLE hCurrentProcess = GetCurrentProcess();
    DWORD dwCurrentProcessId = GetCurrentProcessId();

    char appdata_local[MAX_PATH] = "\0";
    char minidump_path[MAX_PATH] = "\0";

    MINIDUMP_EXCEPTION_INFORMATION mdei; 

    HMODULE hDbgHelp = LoadLibraryA("DBGHELP.DLL");
    HMODULE hAdvapi32 = LoadLibraryA("SHELL32.DLL");

    MiniDumpWriteDump_t pMiniDumpWriteDump = (MiniDumpWriteDump_t) GetProcAddress(
      hDbgHelp, "MiniDumpWriteDump"
    );

    SHGetFolderPathAndSubDirA_t pSHGetFolderPathAndSubDirA =
      (SHGetFolderPathAndSubDirA_t) GetProcAddress(
          hAdvapi32, "SHGetFolderPathAndSubDirA");

    dprint("Global crash handler started\n");

    if (!pSHGetFolderPathAndSubDirA) {
      dprint("Failed to find SHGetFolderPathAndSubDirA\n");
      return;
    }

    if (!pMiniDumpWriteDump) {
      dprint("Failed to find pMiniDumpWriteDump\n");
      return;
    }

    if (!SUCCEEDED(pSHGetFolderPathAndSubDirA(
            NULL, CSIDL_LOCAL_APPDATA | CSIDL_FLAG_CREATE, NULL,
            0, "Microsoft", appdata_local)))
    {
        dprint("Failed to create minidump folder\n");
        return;
    }

    snprintf(
      minidump_path, sizeof(minidump_path) - 1,
      "%s\\tmp_dump_%d.bin", appdata_local, GetCurrentProcessId()
    );

    dprint("Try to write minidump to %s\n", minidump_path);

    hDumpFile = CreateFileA(
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

LONG WINAPI MinidumpFilter(PEXCEPTION_POINTERS pExceptionInfo)
{
  if (pExceptionInfo && pExceptionInfo->ExceptionRecord) {
    dprint(
      "Catch fatal exception: Code: %08x Flags: %08x Address: %p\n",
      pExceptionInfo->ExceptionRecord->ExceptionCode,
      pExceptionInfo->ExceptionRecord->ExceptionFlags,
      pExceptionInfo->ExceptionRecord->ExceptionAddress
    );
  } else {
      dprint("Catch fatal exception somewhere\n");
  }

  CreateMiniDump(pExceptionInfo);
  return EXCEPTION_EXECUTE_HANDLER;
}
