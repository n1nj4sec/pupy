#ifndef POSTMORTEM_H_
#define POSTMORTEM_H_

#include <windows.h>

#pragma pack(push, 4)
typedef struct _MINIDUMP_EXCEPTION_INFORMATION {
  DWORD               ThreadId;
  PEXCEPTION_POINTERS ExceptionPointers;
  BOOL                ClientPointers;
} MINIDUMP_EXCEPTION_INFORMATION, *PMINIDUMP_EXCEPTION_INFORMATION;
#pragma pack(pop)

typedef enum _MINIDUMP_TYPE {
  MiniDumpNormal,
  MiniDumpWithDataSegs,
  MiniDumpWithFullMemory,
  MiniDumpWithHandleData,
  MiniDumpFilterMemory,
  MiniDumpScanMemory,
  MiniDumpWithUnloadedModules,
  MiniDumpWithIndirectlyReferencedMemory,
  MiniDumpFilterModulePaths,
  MiniDumpWithProcessThreadData,
  MiniDumpWithPrivateReadWriteMemory,
  MiniDumpWithoutOptionalData,
  MiniDumpWithFullMemoryInfo,
  MiniDumpWithThreadInfo,
  MiniDumpWithCodeSegs,
  MiniDumpWithoutAuxiliaryState,
  MiniDumpWithFullAuxiliaryState,
  MiniDumpWithPrivateWriteCopyMemory,
  MiniDumpIgnoreInaccessibleMemory,
  MiniDumpWithTokenInformation,
  MiniDumpWithModuleHeaders,
  MiniDumpFilterTriage,
  MiniDumpWithAvxXStateContext,
  MiniDumpWithIptTrace,
  MiniDumpScanInaccessiblePartialPages,
  MiniDumpValidTypeFlags
} MINIDUMP_TYPE;

typedef BOOL (*MiniDumpWriteDump_t)(
    HANDLE hProcess,
    DWORD ProcessId,
    HANDLE hFile,
    MINIDUMP_TYPE DumpType,
    PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam, 
    PVOID UserStreamParam, 
    PVOID CallbackParam
);

LONG WINAPI MinidumpFilter(PEXCEPTION_POINTERS pExceptionInfo);

#endif
