#ifndef POSTMORTEM_H_
#define POSTMORTEM_H_

#include <windows.h>

#ifndef POSTMORTEM_DEST_FOLDER
#define POSTMORTEM_DEST_FOLDER L"Microsoft\\postmortem"
#endif

#pragma pack(push, 4)

typedef enum {
    AddrMode1616,
    AddrMode1632,
    AddrModeReal,
    AddrModeFlat
} ADDRESS_MODE;

typedef struct _IMAGEHLP_SYMBOL64 {
  DWORD   SizeOfStruct;
  DWORD64 Address;
  DWORD   Size;
  DWORD   Flags;
  DWORD   MaxNameLength;
  CHAR    Name[1];
} IMAGEHLP_SYMBOL64, *PIMAGEHLP_SYMBOL64;

typedef struct _IMAGEHLP_SYMBOL {
  DWORD SizeOfStruct;
  DWORD Address;
  DWORD Size;
  DWORD Flags;
  DWORD MaxNameLength;
  CHAR  Name[1];
} IMAGEHLP_SYMBOL, *PIMAGEHLP_SYMBOL;

typedef struct _IMAGEHLP_SYMBOL_STORAGE64 {
    IMAGEHLP_SYMBOL64 symbol;
  CHAR NameStorage[512];
} IMAGEHLP_SYMBOL_STORAGE64;

typedef struct _IMAGEHLP_SYMBOL_STORAGE {
  IMAGEHLP_SYMBOL symbol;
  CHAR NameStorage[512];
} IMAGEHLP_SYMBOL_STORAGE;

typedef struct _tagADDRESS {
  DWORD        Offset;
  WORD         Segment;
  ADDRESS_MODE Mode;
} ADDRESS, *LPADDRESS;

typedef struct _tagADDRESS64 {
  DWORD64      Offset;
  WORD         Segment;
  ADDRESS_MODE Mode;
} ADDRESS64, *LPADDRESS64;

typedef struct _KDHELP64 {
  DWORD64 Thread;
  DWORD   ThCallbackStack;
  DWORD   ThCallbackBStore;
  DWORD   NextCallback;
  DWORD   FramePointer;
  DWORD64 KiCallUserMode;
  DWORD64 KeUserCallbackDispatcher;
  DWORD64 SystemRangeStart;
  DWORD64 KiUserExceptionDispatcher;
  DWORD64 StackBase;
  DWORD64 StackLimit;
  DWORD   BuildVersion;
  DWORD   RetpolineStubFunctionTableSize;
  DWORD64 RetpolineStubFunctionTable;
  DWORD   RetpolineStubOffset;
  DWORD   RetpolineStubSize;
  DWORD64 Reserved0[2];
} KDHELP64, *PKDHELP64;

typedef struct _tagSTACKFRAME64 {
  ADDRESS64 AddrPC;
  ADDRESS64 AddrReturn;
  ADDRESS64 AddrFrame;
  ADDRESS64 AddrStack;
  ADDRESS64 AddrBStore;
  PVOID     FuncTableEntry;
  DWORD64   Params[4];
  BOOL      Far;
  BOOL      Virtual;
  DWORD64   Reserved[3];
  KDHELP64  KdHelp;
} STACKFRAME64, *LPSTACKFRAME64;

typedef struct _KDHELP {
  DWORD Thread;
  DWORD ThCallbackStack;
  DWORD NextCallback;
  DWORD FramePointer;
  DWORD KiCallUserMode;
  DWORD KeUserCallbackDispatcher;
  DWORD SystemRangeStart;
  DWORD ThCallbackBStore;
  DWORD KiUserExceptionDispatcher;
  DWORD StackBase;
  DWORD StackLimit;
  DWORD Reserved[5];
} KDHELP, *PKDHELP;

typedef struct _tagSTACKFRAME {
  ADDRESS AddrPC;
  ADDRESS AddrReturn;
  ADDRESS AddrFrame;
  ADDRESS AddrStack;
  PVOID   FuncTableEntry;
  DWORD   Params[4];
  BOOL    Far;
  BOOL    Virtual;
  DWORD   Reserved[3];
  KDHELP  KdHelp;
  ADDRESS AddrBStore;
} STACKFRAME, *LPSTACKFRAME;

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
