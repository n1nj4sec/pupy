# -*- coding: utf-8 -*-
#Author: ??? and original code from https://github.com/joren485/PyWinPrivEsc/blob/master/RunAsSystem.py
#Contributor(s): @bobsecq

from ctypes import (
    WinDLL, c_uint32, c_char_p,
    c_long, c_uint16, Structure, Union,
    POINTER, create_unicode_buffer, create_string_buffer,
    get_last_error, cast, c_void_p, sizeof, c_int, c_ulong,
    c_wchar, GetLastError, WinError, byref, addressof, c_size_t,
    c_ubyte, resize
)

from ctypes.wintypes import (
    BOOL, LPSTR, LPWSTR, BYTE, LPCSTR, LPCWSTR, USHORT, HANDLE
)

import subprocess
import psutil
import sys
import os

import logging

from os import W_OK, X_OK, R_OK

ntdll    = WinDLL('ntdll',    use_last_error=True)
advapi32 = WinDLL('advapi32', use_last_error=True)
shell32  = WinDLL('shell32',  use_last_error=True)
kernel32 = WinDLL('kernel32', use_last_error=True)
userenv  = WinDLL('userenv',  use_last_error=True)

LPVOID                          = c_void_p
PVOID                           = LPVOID
LPTSTR                          = LPSTR
LPCTSTR                         = LPSTR
PSID                            = PVOID
DWORD                           = c_uint32
INVALID_HANDLE_VALUE            = c_void_p(-1).value
LONG                            = c_long
WORD                            = c_uint16
PULONG                          = c_void_p
LPBYTE                          = c_char_p
SIZE_T                          = c_size_t
ULONG                           = c_ulong

INVALID_HANDLE_VALUE = c_void_p(-1).value
SECURITY_INFORMATION = DWORD

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
TOKEN_ALL_ACCESS                = (
    STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY | \
    TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE | \
    TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT | \
    TOKEN_ADJUST_SESSIONID)

SE_OWNER_DEFAULTED        = 0x0001
SE_GROUP_DEFAULTED        = 0x0002
SE_DACL_PRESENT           = 0x0004
SE_DACL_DEFAULTED         = 0x0008
SE_SACL_PRESENT           = 0x0010
SE_SACL_DEFAULTED         = 0x0020
SE_DACL_AUTO_INHERIT_REQ  = 0x0100
SE_SACL_AUTO_INHERIT_REQ  = 0x0200
SE_DACL_AUTO_INHERITED    = 0x0400
SE_SACL_AUTO_INHERITED    = 0x0800
SE_DACL_PROTECTED         = 0x1000
SE_SACL_PROTECTED         = 0x2000
SE_SELF_RELATIVE          = 0x8000

OBJECT_INHERIT_ACE         = 0x01
CONTAINER_INHERIT_ACE      = 0x02
NO_PROPAGATE_INHERIT_ACE   = 0x04
INHERIT_ONLY_ACE           = 0x08
INHERITED_ACE              = 0x10
SUCCESSFUL_ACCESS_ACE_FLAG = 0x40
FAILED_ACCESS_ACE_FLAG     = 0x80

ACCESS_ALLOWED_ACE_TYPE = 0
ACCESS_DENIED_ACE_TYPE  = 1
SYSTEM_AUDIT_ACE_TYPE   = 2

DELETE                 = 0x00010000 # DE
READ_CONTROL           = 0x00020000 # RC
WRITE_DAC              = 0x00040000 # WDAC
WRITE_OWNER            = 0x00080000 # WO
SYNCHRONIZE            = 0x00100000 # S
ACCESS_SYSTEM_SECURITY = 0x01000000 # AS
GENERIC_READ           = 0x80000000 # GR
GENERIC_WRITE          = 0x40000000 # GW
GENERIC_EXECUTE        = 0x20000000 # GE
GENERIC_ALL            = 0x10000000 # GA

FILE_READ_DATA         = 0x00000001 # RD
FILE_LIST_DIRECTORY    = 0x00000001
FILE_WRITE_DATA        = 0x00000002 # WD
FILE_ADD_FILE          = 0x00000002
FILE_APPEND_DATA       = 0x00000004 # AD
FILE_ADD_SUBDIRECTORY  = 0x00000004
FILE_READ_EA           = 0x00000008 # REA
FILE_WRITE_EA          = 0x00000010 # WEA
FILE_EXECUTE           = 0x00000020 # X
FILE_TRAVERSE          = 0x00000020
FILE_DELETE_CHILD      = 0x00000040 # DC
FILE_READ_ATTRIBUTES   = 0x00000080 # RA
FILE_WRITE_ATTRIBUTES  = 0x00000100 # WA

FILE_GENERIC_READ      = (
    FILE_READ_DATA        | \
    FILE_READ_EA          | \
    FILE_READ_ATTRIBUTES  | \
    READ_CONTROL          | \
    SYNCHRONIZE)

FILE_GENERIC_WRITE     = (
    FILE_WRITE_DATA       | \
    FILE_APPEND_DATA      | \
    FILE_WRITE_EA         | \
    FILE_WRITE_ATTRIBUTES | \
    READ_CONTROL          | \
    SYNCHRONIZE)

FILE_GENERIC_EXECUTE    = (
    FILE_EXECUTE         | \
    FILE_READ_ATTRIBUTES | \
    READ_CONTROL         | \
    SYNCHRONIZE)

FILE_ALL_ACCESS         = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1FF)
FILE_MODIIFY_ACCESS     = FILE_ALL_ACCESS & ~(FILE_DELETE_CHILD | \
                                              WRITE_DAC         | \
                                              WRITE_OWNER)

FILE_READ_EXEC_ACCESS   = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE

FILE_DELETE_ACCESS      = DELETE | SYNCHRONIZE


SE_PRIVILEGE_ENABLED_BY_DEFAULT = (0x00000001)
SE_PRIVILEGE_ENABLED            = (0x00000002)
SE_PRIVILEGE_REMOVED            = (0x00000004)
SE_PRIVILEGE_USED_FOR_ACCESS    = (0x80000000)

OWNER_SECURITY_INFORMATION = 0x00000001
GROUP_SECURITY_INFORMATION = 0x00000002
DACL_SECURITY_INFORMATION = 0x00000004
SACL_SECURITY_INFORMATION = 0x00000008

INVALID_FILE_ATTRIBUTES = -1
FILE_ATTRIBUTE_ARCHIVE = 0x20
FILE_ATTRIBUTE_COMPRESSED = 0x800
FILE_ATTRIBUTE_DEVICE = 0x40
FILE_ATTRIBUTE_DIRECTORY = 0x10
FILE_ATTRIBUTE_ENCRYPTED = 0x4000
FILE_ATTRIBUTE_HIDDEN = 0x02
FILE_ATTRIBUTE_INTEGRITY_STREAM = 0x8000
FILE_ATTRIBUTE_NORMAL = 0x80
FILE_ATTRIBUTE_READONLY = 0x1
FILE_ATTRIBUTE_SYSTEM = 0x4


FILE_EXECUTE = 0x20
FILE_READ_DATA = 0x1
FILE_WRITE_DATA = 0x2

FILE_ADD_FILE = 2
FILE_ADD_SUBDIRECTORY = 4
FILE_APPEND_DATA = 4
FILE_CREATE_PIPE_INSTANCE = 4
FILE_DELETE_CHILD = 0x40
FILE_LIST_DIRECTORY = 1
FILE_READ_ATTRIBUTES = 0x80
FILE_READ_EA = 8
FILE_TRAVERSE = 0x20
FILE_WRITE_ATTRIBUTES = 0x100
FILE_WRITE_EA = 0x10

FILE_ALL_ACCESS = FILE_EXECUTE | FILE_READ_DATA | FILE_WRITE_DATA | \
  FILE_APPEND_DATA | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | \
  FILE_READ_EA | FILE_WRITE_EA

SecurityAnonymous = 0
SecurityIdentification = 1
SecurityImpersonation = 2
SecurityDelegation = 3

SID_SYSTEM = 'S-1-5-18'

SYSTEM_EXTENDED_HANDLE_INFORMATION = 0x00000040
FILE_DEVICE_UNKNOWN = 0x00000022
FILE_ANY_ACCESS = 0x00000000
METHOD_NEITHER = 0x00000003
PROCESS_ALL_ACCESS = 0x001F0FFF
PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
CREATE_NEW_CONSOLE = 0x00000010
CREATE_NO_WINDOW = 0x08000000
DETACHED_PROCESS = 0x00000008
CREATE_UNICODE_ENVIRONMENT = 0x00000400
ENTRIES = 0x00006000
PROCESS_ALL_ACCESS = 0x001fffff

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

ACCESS_MASK = DWORD

class GENERIC_MAPPING(Structure):
    _fields_ = [
        ('GenericRead', ACCESS_MASK),
        ('GenericWrite', ACCESS_MASK),
        ('GenericExecute', ACCESS_MASK),
        ('GenericAll', ACCESS_MASK),
    ]

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

        if res == 0:
            raise WinError(get_last_error())

        return buf[:size.value]

    def __str__(self):
        res = self.get_name()

        if self.is_enabled():
            res += ' (enabled)'

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

class ACL_HEADER(Structure):
    _fields_ = [
        ('AclRevision', BYTE),
        ('Sbz1', BYTE),
        ('AclSize', WORD),
        ('AceCount', WORD),
        ('Sbz2', WORD)
    ]

class SECURITY_DESCRIPTOR(Structure):
    _fields_ = [
        ('Revision', BYTE),
        ('Sbz1', BYTE),
        ('Control', WORD),
        ('Owner', c_void_p),
        ('Group', c_void_p),
        ('Sacl', c_void_p),
        ('Dacl', c_void_p),
    ]
PSECURITY_DESCRIPTOR = POINTER(SECURITY_DESCRIPTOR)

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

class PRIVILEGE_SET_HEADER(Structure):
    _fields_ = [
        ('PrivilegeCount', DWORD),
        ('Control', DWORD)
    ]

class _STARTUPINFOA(Structure):
        _fields_ = [
        ("cb", DWORD),
        ("lpReserved", LPSTR),
        ("lpDesktop", LPSTR),
        ("lpTitle", LPSTR),
        ("dwX", DWORD),
        ("dwY", DWORD),
        ("dwXSize", DWORD),
        ("dwYSize", DWORD),
        ("dwXCountChars", DWORD),
        ("dwYCountChars", DWORD),
        ("dwFillAttribute", DWORD),
        ("dwFlags", DWORD),
        ("wShowWindow", WORD),
        ("cbReserved2", WORD),
        ("lpReserved2", LPBYTE),
        ("hStdInput", HANDLE),
        ("hStdOutput", HANDLE),
        ("hStdError", HANDLE),
    ]

class SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX(Structure):
    _fields_ = [("Object", PVOID),
                ("UniqueProcessId", PVOID),
                ("HandleValue", PVOID),
                ("GrantedAccess", ULONG),
                ("CreatorBackTraceIndex", USHORT),
                ("ObjectTypeIndex", USHORT),
                ("HandleAttributes", ULONG),
                ("Reserved", ULONG)]

class STARTUPINFOEX(Structure):
    _fields_ = [("StartupInfo", STARTUPINFO),
                ("lpAttributeList", PVOID)]

class TOKEN_MANDATORY_LABEL(Structure):
    _fields_ = [
            ('Label', SID_AND_ATTRIBUTES),]

# advapi32

LookupAccountNameW = advapi32.LookupAccountNameW
LookupAccountNameW.restype = BOOL
LookupAccountNameW.argtypes = [
    LPWSTR, LPWSTR, PSID, POINTER(DWORD), LPWSTR, POINTER(DWORD), POINTER(DWORD)
]

LookupAccountSidW = advapi32.LookupAccountSidW
LookupAccountSidW.restype = BOOL
LookupAccountSidW.argtypes = [
    LPWSTR, PSID, LPWSTR, POINTER(DWORD), LPWSTR, POINTER(DWORD), POINTER(DWORD)
]

LookupAccountSidA = advapi32.LookupAccountSidA
LookupAccountSidA.restype = BOOL
LookupAccountSidA.argtypes = [
    LPTSTR, PSID, LPTSTR, POINTER(DWORD), LPTSTR, POINTER(DWORD), POINTER(DWORD)
]

AdjustTokenPrivileges               = advapi32.AdjustTokenPrivileges
AdjustTokenPrivileges.restype       = BOOL
AdjustTokenPrivileges.argtypes      = [
    HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, POINTER(DWORD)
]

CheckTokenMembership                = advapi32.CheckTokenMembership
CheckTokenMembership.restype        = BOOL
CheckTokenMembership.argtypes       = [HANDLE, PSID, POINTER(BOOL)]

ConvertSidToStringSidA              = advapi32.ConvertSidToStringSidA
ConvertSidToStringSidA.restype      = BOOL
ConvertSidToStringSidA.argtypes     = [PSID, POINTER(LPTSTR)]

CreateProcessAsUser                 = advapi32.CreateProcessAsUserA
CreateProcessAsUser.restype         = BOOL
CreateProcessAsUser.argtypes        = [HANDLE, LPTSTR, LPTSTR, PSECURITY_ATTRIBUTES, PSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPTSTR, POINTER(STARTUPINFO), POINTER(PROCESS_INFORMATION)]

CreateWellKnownSid                  = advapi32.CreateWellKnownSid
CreateWellKnownSid.restype          = BOOL
CreateWellKnownSid.argtypes         = [DWORD, POINTER(PSID), LPVOID, POINTER(DWORD)]

DuplicateTokenEx                    = advapi32.DuplicateTokenEx
DuplicateTokenEx.restype            = BOOL
DuplicateTokenEx.argtypes           = [HANDLE, DWORD, PSECURITY_ATTRIBUTES, DWORD, DWORD, POINTER(HANDLE)]

DuplicateToken                      = advapi32.DuplicateToken
DuplicateToken.restype              = BOOL
DuplicateToken.argtypes             = [HANDLE, DWORD, POINTER(HANDLE)]

GetTokenInformation                 = advapi32.GetTokenInformation
GetTokenInformation.restype         = BOOL
GetTokenInformation.argtypes        = [HANDLE, DWORD, LPVOID, DWORD, POINTER(DWORD)]

GetUserNameW                        = advapi32.GetUserNameW
GetUserNameW.restype                = BOOL
GetUserNameW.argtypes               = [LPWSTR, POINTER(DWORD)]

ImpersonateLoggedOnUser             = advapi32.ImpersonateLoggedOnUser
ImpersonateLoggedOnUser.restype     = BOOL
ImpersonateLoggedOnUser.argtypes    = [HANDLE]

LookupPrivilegeValueA               = advapi32.LookupPrivilegeValueA
LookupPrivilegeValueA.restype       = BOOL
LookupPrivilegeValueA.argtypes      = [LPCTSTR, LPCTSTR, PLUID]

OpenProcessToken                    = advapi32.OpenProcessToken
OpenProcessToken.restype            = BOOL
OpenProcessToken.argtypes           = [HANDLE, DWORD, POINTER(HANDLE)]

OpenThreadToken                     = advapi32.OpenThreadToken
OpenThreadToken.restype             = BOOL
OpenThreadToken.argtypes            = [HANDLE, DWORD, BOOL, POINTER(HANDLE)]

RevertToSelf                        = advapi32.RevertToSelf
RevertToSelf.restype                = BOOL
RevertToSelf.argtypes               = []

ImpersonateSelf                     = advapi32.ImpersonateSelf
ImpersonateSelf.restype             = BOOL
ImpersonateSelf.argtypes            = [DWORD]

MapGenericMask                      = advapi32.MapGenericMask
MapGenericMask.argtypes             = [POINTER(DWORD), POINTER(GENERIC_MAPPING)]

GetFileSecurityW                    = advapi32.GetFileSecurityW
GetFileSecurityW.argtypes           = [LPWSTR, SECURITY_INFORMATION, c_void_p,
                                       DWORD, POINTER(DWORD)]
GetFileSecurityW.restype            = BOOL

GetSecurityDescriptorGroup          = advapi32.GetSecurityDescriptorGroup
GetSecurityDescriptorGroup.argtypes = [c_void_p, POINTER(PSID), POINTER(BOOL)]
GetSecurityDescriptorGroup.restype  = BOOL

GetSecurityDescriptorOwner          = advapi32.GetSecurityDescriptorOwner
GetSecurityDescriptorOwner.argtypes = [c_void_p, POINTER(PSID), POINTER(BOOL)]
GetSecurityDescriptorOwner.restype  = BOOL

GetSecurityDescriptorDacl           = advapi32.GetSecurityDescriptorDacl
GetSecurityDescriptorDacl.argtypes  = [c_void_p, POINTER(BOOL), POINTER(c_void_p), POINTER(BOOL)]
GetSecurityDescriptorDacl.restype   = BOOL

class GUID(Structure):
    _fields_ = [
        ('Data1', DWORD),
        ('Data2', WORD),
        ('Data3', WORD),
        ('Data4', BYTE*8)
    ]

class OBJECTS_AND_SID(Structure):
    _fields_ = [
        ('ObjectsPresent', DWORD),
        ('ObjectTypeGuid', GUID),
        ('InheritedObjectTypeGuid', GUID),
        ('pSid', PSID)
    ]

POBJECTS_AND_SID = POINTER(OBJECTS_AND_SID)

class OBJECTS_AND_NAME_W(Structure):
    _fields_ = [
        ('ObjectsPresent', DWORD),
        ('ObjectType', DWORD),
        ('ObjectTypeName', LPWSTR),
        ('InheritedObjectTypeName', LPWSTR),
        ('ptstrName', LPWSTR)
    ]

POBJECTS_AND_NAME_W = POINTER(OBJECTS_AND_NAME_W)

TRUSTEE_IS_SID = 0
TRUSTEE_IS_NAME = 1
TRUSTEE_BAD_FORM = 2
TRUSTEE_IS_OBJECTS_AND_SID = 3
TRUSTEE_IS_OBJECTS_AND_NAME = 4

TRUSTEE_KIND_TEXT = {
    TRUSTEE_IS_SID: 'SID',
    TRUSTEE_IS_NAME: 'NAME',
    TRUSTEE_BAD_FORM: 'BAD',
    TRUSTEE_IS_OBJECTS_AND_SID: 'Objects and SID',
    TRUSTEE_IS_OBJECTS_AND_NAME: 'Objects and NAME'
}

TRUSTEE_IS_UNKNOWN = 0
TRUSTEE_IS_USER = 1
TRUSTEE_IS_GROUP = 2
TRUSTEE_IS_DOMAIN = 3
TRUSTEE_IS_ALIAS = 4
TRUSTEE_IS_WELL_KNOWN_GROUP = 5
TRUSTEE_IS_DELETED = 6
TRUSTEE_IS_INVALID = 7
TRUSTEE_IS_COMPUTER = 8

TRUSTEE_TEXT = {
    TRUSTEE_IS_UNKNOWN: 'Unknown',
    TRUSTEE_IS_USER: 'User',
    TRUSTEE_IS_GROUP: 'Group',
    TRUSTEE_IS_DOMAIN: 'Domain',
    TRUSTEE_IS_ALIAS: 'Alias',
    TRUSTEE_IS_WELL_KNOWN_GROUP: 'Well-Known Group',
    TRUSTEE_IS_DELETED: 'Deleted',
    TRUSTEE_IS_INVALID: 'Invalid',
    TRUSTEE_IS_COMPUTER: 'Computer'
}

NO_INHERITANCE = 0
OBJECT_INHERIT_ACE = 1
CONTAINER_INHERIT_ACE = 2
INHERIT_NO_PROPAGATE = 4
INHERIT_ONLY_ACE = 8

INHERITANCE_TEXT = {
    NO_INHERITANCE: 'NO INHERITANCE',
    OBJECT_INHERIT_ACE: 'OBJECT/ACE',
    CONTAINER_INHERIT_ACE: 'CONTAINER/ACE',
    INHERIT_NO_PROPAGATE: 'NO PROPAGATE',
    INHERIT_ONLY_ACE: 'ONLY ACE'
}

class TRUSTEE_W_NAME(Union):
    _fields_ = [
        ('ptstrName', LPWSTR),
        ('pSid', PSID),
        ('pObjectsAndSid', POBJECTS_AND_SID),
        ('pObjectsAndName', POBJECTS_AND_NAME_W),
    ]

class TRUSTEE_W(Structure):
    _fields_ = [
        # Unsupported
        ('pMultipleTrustee', c_void_p),
        ('MultipleTrusteeOperation', DWORD),
        # Supported
        ('TrusteeForm', DWORD),
        ('TrusteeType', DWORD),
        ('TrusteeName', TRUSTEE_W_NAME),
    ]

class ACE_HEADER(Structure):
    _fields_ = [
        ('AceType', BYTE),
        ('AceFlags', BYTE),
        ('AceSize', WORD)
    ]

ACCESS_ALLOWED_ACE_TYPE = 0
ACCESS_DENIED_ACE_TYPE = 1
SYSTEM_AUDIT_ACE_TYPE = 2
SYSTEM_ALARM_ACE_TYPE = 3

class ACCESS_ALLOWED_ACE(Structure):
    _fields_ = [
        ('Header', ACE_HEADER),
        ('Mask', DWORD),
        ('SidStart', DWORD),
    ]

PACCESS_ALLOWED_ACE = POINTER(ACCESS_ALLOWED_ACE)

NOT_USED_ACCESS = 0
GRANT_ACCESS = 1
SET_ACCESS = 2
DENY_ACCESS = 3
REVOKE_ACCESS = 4
SET_AUDIT_SUCCESS = 5
SET_AUDIT_FAILURE = 6

ACCESS_MODE_TEXT = {
    NOT_USED_ACCESS: '',
    GRANT_ACCESS: '(GRANT)',
    SET_ACCESS: '(SET)',
    DENY_ACCESS: '(DENY)',
    REVOKE_ACCESS: '(REVOKE)',
    SET_AUDIT_SUCCESS: '(AUDIT SUCCESS)',
    SET_AUDIT_FAILURE: '(AUDIT FAILURE)'
}

ACE_ACCESS_DELETE        = (0x00010000L)
ACE_ACCESS_READ_CONTROL  = (0x00020000L)
ACE_ACCESS_WRITE_DAC     = (0x00040000L)
ACE_ACCESS_WRITE_OWNER   = (0x00080000L)
ACE_ACCESS_SYNCHRONIZE   = (0x00100000L)

STANDARD_RIGHTS_REQUIRED = (0x000F0000L)

STANDARD_RIGHTS_READ     = (READ_CONTROL)
STANDARD_RIGHTS_WRITE    = (READ_CONTROL)
STANDARD_RIGHTS_EXECUTE  = (READ_CONTROL)
STANDARD_RIGHTS_ALL      = (0x001F0000L)
SPECIFIC_RIGHTS_ALL      = (0x0000FFFFL)

class EXPLICIT_ACCESS_W(Structure):
    _fields_ = [
        ('grfAccessPermissions', DWORD),
        ('grfAccessMode', DWORD),
        ('grfInheritance', DWORD),
        ('Trustee', TRUSTEE_W)
    ]

PEXPLICIT_ACCESS_W = POINTER(EXPLICIT_ACCESS_W)

AclRevisionInformation = 0
AclSizeInformation     = 1

GetExplicitEntriesFromAclW          = advapi32.GetExplicitEntriesFromAclW
GetExplicitEntriesFromAclW.argtypes = [c_void_p, POINTER(c_ulong), POINTER(PEXPLICIT_ACCESS_W)]
GetExplicitEntriesFromAclW.restype  = DWORD

GetAclInformation                   = advapi32.GetAclInformation
GetAclInformation.argtypes          = [c_void_p, c_void_p, DWORD, DWORD]
GetAclInformation.restype           = BOOL

GetAce                              = advapi32.GetAce
GetAce.argtypes                     = [c_void_p, DWORD, POINTER(PACCESS_ALLOWED_ACE)]
GetAce.restype                      = BOOL

IsValidSecurityDescriptor           = advapi32.IsValidSecurityDescriptor
IsValidSecurityDescriptor.argtypes  = [c_void_p]
GetFileSecurityW.restype            = BOOL

AccessCheck                         = advapi32.AccessCheck
AccessCheck.restype                 = BOOL
AccessCheck.argtypes                = [c_void_p, HANDLE, DWORD, POINTER(GENERIC_MAPPING),
                                       c_void_p, POINTER(DWORD), POINTER(DWORD), POINTER(BOOL)]


GetSidSubAuthorityCount             = advapi32.GetSidSubAuthorityCount
GetSidSubAuthorityCount.argtypes    = [c_void_p]
GetSidSubAuthorityCount.restype     = POINTER(c_ubyte)

GetSidSubAuthority                  = advapi32.GetSidSubAuthority
GetSidSubAuthority.argtypes         = [c_void_p, DWORD]
GetSidSubAuthority.restype          = POINTER(DWORD)

CreateProcessW                       = kernel32.CreateProcessW #Unicode version
CreateProcessW.restype               = BOOL
CreateProcessW.argtypes              = [LPCWSTR, LPWSTR, PSECURITY_ATTRIBUTES, PSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, POINTER(STARTUPINFOEX), POINTER(PROCESS_INFORMATION)]

CreateProcessA                       = kernel32.CreateProcessA #Unicode version
CreateProcessA.restype               = BOOL
CreateProcessA.argtypes              = [LPCSTR, LPSTR, PSECURITY_ATTRIBUTES, PSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, POINTER(STARTUPINFOEX), POINTER(PROCESS_INFORMATION)]

# kernel32

GetFileAttributesW                  = kernel32.GetFileAttributesW
GetFileAttributesW.argtypes         = [LPWSTR]
GetFileAttributesW.restype          = DWORD

CloseHandle                         = kernel32.CloseHandle
CloseHandle.restype                 = BOOL
CloseHandle.argtypes                = [HANDLE]

GetCurrentProcess                   = kernel32.GetCurrentProcess
GetCurrentProcess.restype           = HANDLE
GetCurrentProcess.argtypes          = []

GetCurrentThread                    = kernel32.GetCurrentThread
GetCurrentThread.restype            = HANDLE
GetCurrentThread.argtypes           = []

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

InitializeProcThreadAttributeList          = kernel32.InitializeProcThreadAttributeList
InitializeProcThreadAttributeList.restype  = BOOL
InitializeProcThreadAttributeList.argtypes = [PVOID, DWORD, DWORD, POINTER(SIZE_T)]

UpdateProcThreadAttribute                  = kernel32.UpdateProcThreadAttribute
UpdateProcThreadAttribute.restype          = BOOL
UpdateProcThreadAttribute.argtypes         = [PVOID, DWORD, PVOID, PVOID, SIZE_T, PVOID, POINTER(SIZE_T)]

# ntdll
RtlGetVersion                       = ntdll.RtlGetVersion
RtlGetVersion.restype               = DWORD
RtlGetVersion.argtypes              = [POSVERSIONINFOEXW]

# shell32

IsUserAnAdmin                       = shell32.IsUserAnAdmin
IsUserAnAdmin.restype               = BOOL
IsUserAnAdmin.argtypes              = []

# userenv

CREATE_NEW_CONSOLE          = 0x00000010
CREATE_UNICODE_ENVIRONMENT  = 0x00000400
NORMAL_PRIORITY_CLASS       = 0x00000020

CreateEnvironmentBlock = userenv.CreateEnvironmentBlock
CreateEnvironmentBlock.restype = BOOL
CreateEnvironmentBlock.argtypes = [
    POINTER(c_void_p), c_void_p, c_int
]

DestroyEnvironmentBlock = userenv.DestroyEnvironmentBlock
DestroyEnvironmentBlock.argtypes = [
    c_void_p
]

# various

ERROR_SUCCESS = 0
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_ACCESS_DENIED = 5
ERROR_INVALID_PARAMETER = 87
ERROR_NOT_ALL_ASSIGNED = 1300

def GetUserName():
    nSize = DWORD(0)
    GetUserNameW(None, byref(nSize))
    error = GetLastError()

    if error and error != ERROR_INSUFFICIENT_BUFFER:
        raise WinError(error)

    lpBuffer = create_unicode_buffer(u'', nSize.value + 1)

    if not GetUserNameW(lpBuffer, byref(nSize)):
        raise WinError(get_last_error())

    return lpBuffer.value

def GetTokenSid(hToken):

    """Retrieve SID from Token"""

    dwSize = DWORD(0)
    pStringSid = LPSTR()
    TokenUser = 1

    if not GetTokenInformation(hToken, TokenUser, byref(TOKEN_USER()), 0, byref(dwSize)):
        error = get_last_error()
        if error != ERROR_INSUFFICIENT_BUFFER:
            raise WinError(error)

    address = LocalAlloc(0x0040, dwSize)
    if GetTokenInformation(hToken, TokenUser, address, dwSize, byref(dwSize)):
        pToken_User = cast(address, POINTER(TOKEN_USER))
        ConvertSidToStringSidA(pToken_User.contents.User.Sid, byref(pStringSid))
        sid = pStringSid.value

    LocalFree(address)
    return sid

def EnablePrivilege(privilegeStr, hToken=None, exc=True):

    """Enable Privilege on token, if no token is given the function gets the token of the current process."""

    close_hToken = False

    if type(privilegeStr) == unicode:
        privilege = privilegeStr.encode('latin1')
    else:
        privilege = str(privilegeStr)

    if hToken is None:
        hToken = HANDLE(INVALID_HANDLE_VALUE)
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, False, GetCurrentProcessId())
        if not hProcess:
            raise WinError(get_last_error())

        dwError = None
        if not OpenProcessToken(hProcess, (TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY), byref(hToken)):
            dwError = get_last_error()

        CloseHandle(hProcess)

        if dwError:
            raise WinError(dwError)

        close_hToken = True

    bSuccess = False

    try:
        privilege_id = LUID()
        if not LookupPrivilegeValueA(None, privilege, byref(privilege_id)):
            raise WinError(get_last_error())

        SE_PRIVILEGE_ENABLED = 0x00000002
        laa = LUID_AND_ATTRIBUTES(privilege_id, SE_PRIVILEGE_ENABLED)
        tp  = TOKEN_PRIVILEGES(1, laa)

        if AdjustTokenPrivileges(hToken, False, byref(tp), sizeof(tp), None, None):
            error = get_last_error()
            if error == ERROR_SUCCESS:
                bSuccess = True
            elif exc:
                if error == ERROR_NOT_ALL_ASSIGNED:
                    raise ValueError(error, 'Could not set {} (access denied)'.format(privilege))
                else:
                    raise WinError(error)
        elif exc:
            WinError(get_last_error())

    finally:
        if close_hToken:
            CloseHandle(hToken)

    return bSuccess

def ListSids():
    sids=[]

    for proc in psutil.process_iter():
        try:
            pinfo = proc.as_dict(attrs=['pid', 'username', 'name'])
        except psutil.NoSuchProcess:
            pass

        pid = int(pinfo['pid'])

        if pid <= 4:
            continue

        if pinfo['username'] is None:
            continue

        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
        if not hProcess:
            error = get_last_error()
            if error != ERROR_INVALID_PARAMETER:
                # Process exited, dead, whatever
                raise WinError(get_last_error())

            continue

        hToken = HANDLE(INVALID_HANDLE_VALUE)

        bTokenOk = OpenProcessToken(hProcess, tokenprivs, byref(hToken))
        error = get_last_error()

        CloseHandle(hProcess)

        if not bTokenOk:
            if error == ERROR_ACCESS_DENIED:
                continue

            raise WinError(error)

        try:
            sids.append((pinfo['pid'], pinfo['name'], GetTokenSid(hToken), pinfo['username']))
        finally:
            CloseHandle(hToken)

    return list(sids)

def getProcessToken(pid):
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
    if not hProcess:
        raise WinError(get_last_error())

    hToken = HANDLE(INVALID_HANDLE_VALUE)
    dwError = None

    if not OpenProcessToken(hProcess, tokenprivs, byref(hToken)):
        dwError = get_last_error()

    CloseHandle(hProcess)

    if dwError:
        raise WinError(dwError)

    return hToken

def get_process_token():
    """
    Get the current process token
    """
    token = HANDLE()
    if not OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, token):
        raise WinError(get_last_error())

    return token

def gethTokenFromPid(pid, exc=True):
    hToken = HANDLE(INVALID_HANDLE_VALUE)

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, False, int(pid))
    if not hProcess:
        if exc:
            raise WinError(get_last_error())
        else:
            return None

    dwError = None
    if not OpenProcessToken(hProcess, tokenprivs, byref(hToken)):
        dwError = get_last_error()

    CloseHandle(hProcess)

    if dwError:
        raise WinError(dwError)

    return hToken

def getSidToken(token_sid):

    # trying to get system privileges
    if token_sid == SID_SYSTEM:
        sids = ListSids()
        for sid in sids:
            if 'winlogon' not in sid[1].lower():
                continue

            hToken = gethTokenFromPid(sid[0], exc=False)
            if not hToken:
                continue

            return hToken

    # trying to impersonate a token
    else:
        for p in psutil.process_iter():
            if p.pid <= 4:
                continue

            hToken = gethTokenFromPid(p.pid, exc=False)
            if not hToken:
                continue

            if GetTokenSid(hToken) == token_sid:
                return hToken

            CloseHandle(hToken)

def impersonate_pid(pid, close=True):
    EnablePrivilege("SeDebugPrivilege")

    hToken = getProcessToken(pid)
    if not hToken:
        return None

    hTokendupe = impersonate_token(hToken)

    if close and hTokendupe:
        CloseHandle(hTokendupe)

    return hTokendupe

def impersonate_sid(sid, close=True):

    if not sid.startswith('S-1-'):
        sid = sidbyname(sid)
        if not sid:
            raise ValueError('Unknown username {}'.format(sid.encode('utf-8')))

    EnablePrivilege("SeDebugPrivilege")
    hToken = getSidToken(sid)
    if not hToken:
        raise ValueError('Could not get token for SID {}'.format(sid))

    hTokendupe = impersonate_token(hToken)
    if close and hTokendupe:
        CloseHandle(hTokendupe)

    if not hTokendupe:
        raise ValueError('Could not impersonate token for SID {}'.format(sid))

    return hTokendupe

global_ref = None

def impersonate_sid_long_handle(*args, **kwargs):
    global global_ref

    hTokendupe = impersonate_sid(*args, **kwargs)
    if not hTokendupe:
        return None

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
    if not hTokendupe:
        return None

    try:
        if global_ref is not None:
            CloseHandle(global_ref)
    except:
        pass

    global_ref = hTokendupe
    return addressof(hTokendupe)

def impersonate_token(hToken):
    EnablePrivilege('SeDebugPrivilege')
    EnablePrivilege('SeImpersonatePrivilege')

    hTokendupe = HANDLE(INVALID_HANDLE_VALUE)

    SecurityImpersonation = 2
    TokenPrimary = 1

    if not DuplicateTokenEx(
        hToken, TOKEN_ALL_ACCESS, None, SecurityImpersonation,
        TokenPrimary, byref(hTokendupe)):
        raise WinError(get_last_error())

    CloseHandle(hToken)

    try:
        EnablePrivilege('SeAssignPrimaryTokenPrivilege', hToken=hTokendupe, exc=False)
        EnablePrivilege('SeIncreaseQuotaPrivilege', hToken=hTokendupe, exc=False)

        if not ImpersonateLoggedOnUser(hTokendupe):
            raise WinError(get_last_error())

    except Exception:
        CloseHandle(hTokendupe)
        raise

    return hTokendupe

def isSystem():
    sids = ListSids()
    for sid in sids:
        if sid[0] == os.getpid():
            if sid[2] == SID_SYSTEM:
                return True
    return False

def create_proc_as_sid(sid, prog='cmd.exe'):
    if not sid.startswith('S-1-'):
        sid = sidbyname(sid)
        if not sid:
            raise ValueError('Unknown username {}'.format(sid.encode('utf-8')))

    hTokendupe = impersonate_sid(sid, close=False)

    try:
        pid = start_proc_with_token([prog], hTokendupe)
    finally:
        CloseHandle(hTokendupe)

    return pid

def getsystem(prog='cmd.exe'):
    return create_proc_as_sid(SID_SYSTEM, prog=prog)

def start_proc_with_token(args, hTokendupe, hidden=True):
    ##Start the process with the token.
    lpProcessInformation = PROCESS_INFORMATION()
    lpStartupInfo = STARTUPINFO()
    if hidden:
        lpStartupInfo.dwFlags = subprocess.STARTF_USESHOWWINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
        lpStartupInfo.wShowWindow = subprocess.SW_HIDE

    dwCreationflag = NORMAL_PRIORITY_CLASS | CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE

    cenv = c_void_p()

    if not CreateEnvironmentBlock(byref(cenv), hTokendupe, 0):
        raise WinError(get_last_error())

    if not CreateProcessAsUser(
        hTokendupe, None, ' '.join(args), None, None, True,
        dwCreationflag, cenv, None,
        byref(lpStartupInfo), byref(lpProcessInformation)):
        raise WinError(get_last_error())

    return lpProcessInformation.dwProcessId

def rev2self():
    global global_ref

    RevertToSelf()

    if global_ref is not None:
        CloseHandle(global_ref)

    global_ref = None

def get_currents_privs():
    '''
    Get all privileges associated with the current process.
    '''
    dwSize = DWORD()
    hToken = get_process_token()

    try:
        if not GetTokenInformation(
            hToken, TOKEN_INFORMATION_CLASS.TokenPrivileges, None, 0, byref(dwSize)):

            error = get_last_error()
            if error != ERROR_INSUFFICIENT_BUFFER:
                raise WinError(error)

        cBuffer = create_string_buffer(dwSize.value)
        if not GetTokenInformation(
            hToken, TOKEN_INFORMATION_CLASS.TokenPrivileges,
            cBuffer, dwSize.value, byref(dwSize)):
            raise WinError(get_last_error())

    finally:
        CloseHandle(hToken)

    privs = tuple(
        (x.get_name(), x.is_enabled()) for x in cast(
            cBuffer, POINTER(TOKEN_PRIVS)).contents
    )

    return privs

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
        'major_version': os_version.dwMajorVersion.real,
        'minor_version': os_version.dwMinorVersion.real,
        'build_number': os_version.dwBuildNumber.real
    }

def access(path, mode):
    requested_information = OWNER_SECURITY_INFORMATION | \
        GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION

    dwSize = DWORD(0)
    hToken = HANDLE()
    access_desired = 0

    if type(path) == str:
        path = path.decode('utf-8')

    attributes = GetFileAttributesW(path)

    if attributes == INVALID_FILE_ATTRIBUTES:
        return False

    if mode == os.F_OK:
        return True

    if (mode & W_OK) and (attributes & FILE_ATTRIBUTE_READONLY) and \
      not (attributes & FILE_ATTRIBUTE_DIRECTORY):
        return False

    success = GetFileSecurityW(path, requested_information,
        c_void_p(0), 0, byref(dwSize))

    if not success and get_last_error() != ERROR_INSUFFICIENT_BUFFER:
        return False

    pSDBuf = create_string_buffer(dwSize.value)
    can_read_access = GetFileSecurityW(
        path, requested_information, pSDBuf,
        dwSize, byref(dwSize))

    if not can_read_access:
        return False

    if not IsValidSecurityDescriptor(pSDBuf):
        return False

    is_access_granted = False

    if not OpenProcessToken(
        GetCurrentProcess(),
        TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_DUPLICATE | STANDARD_RIGHTS_READ,
        byref(hToken)):

        return False

    hImpersonatedToken = HANDLE()
    if not DuplicateToken(hToken, SecurityImpersonation, byref(hImpersonatedToken)):
        CloseHandle(hToken)
        return False

    access_desired = 0

    mapping = GENERIC_MAPPING()

    if (mode & X_OK):
        access_desired |= FILE_EXECUTE
    if (mode & R_OK):
        access_desired |= FILE_READ_DATA
    if (mode & W_OK):
        access_desired |= FILE_WRITE_DATA

    mapping.GenericRead = FILE_READ_DATA
    mapping.GenericWrite = FILE_WRITE_DATA
    mapping.GenericExecute = FILE_EXECUTE
    mapping.GenericAll = FILE_ALL_ACCESS

    access_desired = DWORD(access_desired)

    MapGenericMask(byref(access_desired), byref(mapping))

    ps = PRIVILEGE_SET_HEADER()
    pps = byref(ps)
    pps_size = DWORD(sizeof(ps))
    access_granted = DWORD(0)
    is_access_granted_bool = BOOL(False)

    if not AccessCheck(
        pSDBuf, hImpersonatedToken, access_desired, byref(mapping), pps,
        byref(pps_size), byref(access_granted), byref(is_access_granted_bool)):

        if get_last_error() == ERROR_INSUFFICIENT_BUFFER:
            pps = create_string_buffer(pps_size.value)

        AccessCheck(
            pSDBuf, hImpersonatedToken, access_desired, byref(mapping), pps,
            byref(pps_size), byref(access_granted), byref(is_access_granted_bool))

    is_access_granted = bool(is_access_granted_bool)

    CloseHandle(hImpersonatedToken)
    CloseHandle(hToken)

    return is_access_granted

def strsid(sid, exc=True):
    StringSid = LPTSTR()

    if ConvertSidToStringSidA(sid, byref(StringSid)):
        sid = str(StringSid.value)
        LocalFree(StringSid)
        return sid

    if not exc:
        return None

    raise WinError(get_last_error())

def namebysid(sid, domain=None):
    Name = LPWSTR()
    cbName = DWORD(0)

    ReferencedDomainName = LPWSTR()
    cchReferencedDomainName = DWORD(0)

    peUse = DWORD(0)

    if LookupAccountSidW(domain, sid, Name, byref(cbName),
        ReferencedDomainName, byref(cchReferencedDomainName), byref(peUse)) or \
        get_last_error() != ERROR_INSUFFICIENT_BUFFER or cbName.value <= 0 or \
        cchReferencedDomainName.value <= 0:
        return '', ''

    Name = create_unicode_buffer(cbName.value)
    ReferencedDomainName = create_unicode_buffer(cchReferencedDomainName.value)

    if not LookupAccountSidW(domain, sid, Name, byref(cbName),
        ReferencedDomainName, byref(cchReferencedDomainName), byref(peUse)):
        raise WinError(get_last_error())

    if Name.value == 'None':
        return '', ''

    return Name.value, ReferencedDomainName.value

def sidbyname(name, domain=None):
    if type(name) == str:
        name = name.decode('utf-8')

    Sid = PSID()
    cbSid = DWORD(0)

    ReferencedDomainName = LPWSTR()
    cchReferencedDomainName = DWORD(0)

    peUse = DWORD(0)

    if LookupAccountNameW(domain, name, Sid, byref(cbSid),
        ReferencedDomainName, byref(cchReferencedDomainName), byref(peUse)) or \
        get_last_error() != ERROR_INSUFFICIENT_BUFFER or cbSid.value <= 0 or \
        cchReferencedDomainName.value <= 0:
        return None

    Sid = create_string_buffer(cbSid.value)
    ReferencedDomainName = create_unicode_buffer(cchReferencedDomainName.value)

    if not LookupAccountNameW(domain, name, Sid, byref(cbSid),
        ReferencedDomainName, byref(cchReferencedDomainName), byref(peUse)):
        raise WinError(get_last_error())

    return strsid(Sid)

def _getfileinfo(path, requested_information=0):

    if type(path) == str:
        path = path.decode('utf-8')

    requested_information |= OWNER_SECURITY_INFORMATION | \
      GROUP_SECURITY_INFORMATION

    dwSize = DWORD(0)

    success = GetFileSecurityW(path, requested_information,
        c_void_p(0), 0, byref(dwSize))

    if not success and get_last_error() != ERROR_INSUFFICIENT_BUFFER:
        raise WinError(get_last_error())

    pSDBuf = create_string_buffer(dwSize.value)
    can_read_access = GetFileSecurityW(
        path, requested_information, pSDBuf,
        dwSize, byref(dwSize))

    if not can_read_access:
        raise WinError(get_last_error())

    if not IsValidSecurityDescriptor(pSDBuf):
        raise WinError(get_last_error())

    GSid = PSID()
    USid = PSID()
    bDefault = BOOL()

    if GetSecurityDescriptorOwner(pSDBuf, byref(USid), byref(bDefault)) and \
      GetSecurityDescriptorGroup(pSDBuf, byref(GSid), byref(bDefault)):
        return pSDBuf, USid, GSid

    raise WinError(get_last_error())

def getfileowner(path, as_sid=True):
    pSDBuf, USid, GSid = _getfileinfo(path)

    if as_sid:
        return strsid(USid), strsid(GSid)
    else:
        return namebysid(USid), namebysid(GSid)

    raise WinError(get_last_error())

# https://stackoverflow.com/questions/34698927/python-get-windows-folder-acl-permissions

class Ace(object):
    __slots__ = (
        'ace_type', 'flags', 'mask', 'mapped_mask', 'trustee'
    )

    def __init__(self, ace_type, flags, mask, trustee):
        self.ace_type = ace_type
        self.flags = flags
        self.mask = mask
        self.trustee = trustee
        self.mapped_mask = self._map_generic(mask)

    @staticmethod
    def _map_generic(mask):
        if mask & GENERIC_READ:
            mask = (mask & ~GENERIC_READ) | FILE_GENERIC_READ
        if mask & GENERIC_WRITE:
            mask = (mask & ~GENERIC_WRITE) | FILE_GENERIC_WRITE
        if mask & GENERIC_EXECUTE:
            mask = (mask & ~GENERIC_EXECUTE) | FILE_GENERIC_EXECUTE
        if mask & GENERIC_ALL:
            mask = (mask & ~GENERIC_ALL) | FILE_ALL_ACCESS
        return mask

    def inherited(self):         # I
        return bool(self.flags & INHERITED_ACE)

    def object_inherit(self):    # OI
        return bool(self.flags & OBJECT_INHERIT_ACE)

    def container_inherit(self): # CI
        return bool(self.flags & CONTAINER_INHERIT_ACE)

    def inherit_only(self):      # IO
        return bool(self.flags & INHERIT_ONLY_ACE)

    def no_propagate(self):      # NP
        return bool(self.flags & NO_PROPAGATE_INHERIT_ACE)

    def no_access(self):         # N
        return self.mapped_mask == 0

    def full_access(self):       # F
        return bool(self.mapped_mask & FILE_ALL_ACCESS)

    def modify_access(self):     # M
        return bool(self.mapped_mask & FILE_MODIIFY_ACCESS)

    def read_exec_access(self):  # RX
        return bool(self.mapped_mask & FILE_READ_EXEC_ACCESS)

    def read_only_access(self):  # R
        return bool(self.mapped_mask == FILE_GENERIC_READ)

    def write_only_access(self): # W
        return bool(self.mapped_mask == FILE_GENERIC_WRITE)

    def delete_access(self):     # D
        return bool(self.mapped_mask & FILE_DELETE_ACCESS)

    def get_file_rights(self):
        if self.no_access():
            return ['N']

        if self.full_access():
            return ['F']

        if self.modify_access():
            return ['M']

        if self.read_exec_access():
            return ['RX']

        if self.read_only_access():
            return ['R']

        if self.write_only_access():
            return ['W']

        if self.delete_access():
            return ['D']

        rights = []

        for right, name in (
            (DELETE, 'DE'), (READ_CONTROL, 'RC'),
            (WRITE_DAC, 'WDAC'), (WRITE_OWNER, 'WO'),
            (SYNCHRONIZE, 'S'), (ACCESS_SYSTEM_SECURITY, 'AS'),
            (GENERIC_READ, 'GR'), (GENERIC_WRITE, 'GW'),
            (GENERIC_EXECUTE, 'GE'), (GENERIC_ALL, 'GA'),
            (FILE_READ_DATA, 'RD'), (FILE_WRITE_DATA, 'WD'),
            (FILE_APPEND_DATA, 'AD'), (FILE_READ_EA, 'REA'),
            (FILE_WRITE_EA, 'WEA'), (FILE_EXECUTE, 'X'),
            (FILE_DELETE_CHILD, 'DC'),
            (FILE_READ_ATTRIBUTES, 'RA'),
            (FILE_WRITE_ATTRIBUTES, 'WA')):

            if self.mask & right:
                rights.append(name)

        return rights

    def granted_access(self, mask):
        return bool(self.mapped_mask & self._map_generic(mask))

    def __str__(self):
        access = []

        if self.ace_type == ACCESS_DENIED_ACE_TYPE:
            access.append('{DENY}')
        elif self.ace_type == SYSTEM_AUDIT_ACE_TYPE:
            access.append('{AUDIT}')
        elif self.ace_type == SYSTEM_ALARM_ACE_TYPE:
            access.append('{ALARM}')

        if self.inherited():
            access.append('(I)')

        if self.object_inherit():
            access.append('(OI)')

        if self.container_inherit():
            access.append('(CI)')

        if self.inherit_only():
            access.append('(IO)')

        if self.no_propagate():
            access.append('(NP)')

        access.append('(%s)' % ','.join(self.get_file_rights()))

        return '%s: %s' % (self.trustee, ''.join(access))

def getfileowneracls(path):
    infos = []

    if type(path) == str:
        path = path.decode('utf-8')

    requested_information = OWNER_SECURITY_INFORMATION | \
        GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION

    pSDBuf, USid, GSid = _getfileinfo(path, requested_information)

    owner_sid = strsid(USid)
    group_sid = strsid(GSid)

    owner_name, owner_domain = namebysid(USid)
    group_name, group_domain = namebysid(GSid)

    owner = owner_sid, owner_name, owner_domain
    group = group_sid, group_name, group_domain

    infos.append(owner)
    infos.append(group)

    pACL = c_void_p()
    bDaclPresent = BOOL()
    bDaclDefaulted = BOOL(True)

    if not GetSecurityDescriptorDacl(
        pSDBuf, byref(bDaclPresent),
        byref(pACL), byref(bDaclDefaulted)):
        raise WinError(get_last_error())

    if not bDaclPresent:
        infos.append(None)
        return infos

    ACLs = []

    i = 0
    while True:
        ace = PACCESS_ALLOWED_ACE()
        if not GetAce(pACL, i, byref(ace)):
            break

        ace = ace.contents
        sid = byref(ace, ACCESS_ALLOWED_ACE.SidStart.offset)

        name, domain = namebysid(sid)
        sid = strsid(sid)
        trustee = sid

        if name:
            if domain:
                trustee = u'{}\\{} ({})'.format(
                    domain, name, sid
                )
            else:
                trustee = u'{} ({})'.format(
                    name, sid
                )

        ace = Ace(ace.Header.AceType, ace.Header.AceFlags, ace.Mask, trustee)
        ACLs.append(ace)

        i += 1

    infos.append(ACLs)
    return infos

def create_new_process_from_ppid(ppid, cmd):
    """
    Create new process as SYSTEM via Handle Inheritance specifying privileged parent
    Returns True if no problem
    Based on : https://github.com/decoder-it/psgetsystem/blob/master/psgetsys.ps1
    """
    lpAttributeList = None
    lpSize = c_size_t(0)

    EnablePrivilege("SeDebugPrivilege")

    # 1.Call with null lpAttributeList first to get back the lpSize
    InitializeProcThreadAttributeList(None, 1, 0, byref(lpSize))

    # 2.Initialize the attribute list
    lpAttributeList = create_string_buffer(lpSize.value)
    if not InitializeProcThreadAttributeList(lpAttributeList, 1, 0, byref(lpSize)):
        raise WinError(get_last_error())

    # 3.Add attribute to attribute list (we now know buffer size for the specified number of attributes we allocate and initialize AttributeList)
    #lpValue = PVOID(ppid) # Handle to specified parent

    handle = OpenProcess(PROCESS_ALL_ACCESS, False, int(ppid))
    if not handle:
        raise WinError(get_last_error())

    last_error = None
    hHandle = HANDLE(handle)

    if not UpdateProcThreadAttribute(
        lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
        byref(hHandle), sizeof(hHandle), 0, None):
        last_error = get_last_error()
        CloseHandle(handle)
        raise WinError(last_error)

    #gaining a shell...
    lpProcessInformation = PROCESS_INFORMATION()

    lpStartupInfo              = STARTUPINFOEX()
    lpStartupInfo.StartupInfo.lpReserved   = 0
    lpStartupInfo.StartupInfo.lpDesktop    = 0
    lpStartupInfo.StartupInfo.lpTitle      = 0
    lpStartupInfo.StartupInfo.dwFlags      = 0
    lpStartupInfo.StartupInfo.cbReserved2  = 0
    lpStartupInfo.StartupInfo.lpReserved2  = 0
    lpStartupInfo.StartupInfo.cb = sizeof(lpStartupInfo)
    lpStartupInfo.lpAttributeList = addressof(lpAttributeList)

    lpProcessInformation              = PROCESS_INFORMATION()
    lpProcessInformation.hProcess     = INVALID_HANDLE_VALUE
    lpProcessInformation.hThread      = INVALID_HANDLE_VALUE
    lpProcessInformation.dwProcessId  = 0
    lpProcessInformation.dwThreadId   = 0

    dwCreationFlags = (CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT)

    if not CreateProcessW(
        None, cmd, None, None, 0, dwCreationFlags, None,
        None,  byref(lpStartupInfo), byref(lpProcessInformation)):
        raise WinError(get_last_error())

    CloseHandle(handle)
    return lpProcessInformation.dwProcessId

def get_integrity_level(pid):
    '''
    Returns the integrity level of a specific pid
    Notice the process running this method should have less or same 'pivileges' than the pid for getting the integrity level.
    e.g. a process running with medium integrity level can't access to integrity level information of a process running with the system or high integrity level.
    You can test with Process Explorer.
    Returns 0, 1, 2, 3 ,4, 5 or 6 if an error. Otherwise returns string (intergrity level)
    '''

    mapping = {
        0x0000: u'Untrusted',
        0x1000: u'Low',
        0x2000: u'Medium',
        0x2100: u'Medium high',
        0x3000: u'High',
        0x4000: u'System',
        0x5000: u'Protected process',
    }

    #TOKEN_READ = DWORD(0x20008)
    TokenIntegrityLevel = c_uint32(25)
    token = c_void_p()

    proc_handle = OpenProcess(PROCESS_QUERY_INFORMATION, False, int(pid))
    if proc_handle == 0:
        return 0

    if not OpenProcessToken(
            proc_handle,
            TOKEN_READ,
            byref(token)):
        logging.error('Failed to get process token')
        return 1

    if token.value == 0:
        logging.error('Got a NULL token')
        return 2
    try:
        info_size = DWORD()
        if GetTokenInformation(
                token,
                TokenIntegrityLevel,
                c_void_p(),
                info_size,
                byref(info_size)):
            logging.error('GetTokenInformation() failed expectation')
            return 3

        if info_size.value == 0:
            logging.error('GetTokenInformation() returned size 0')
            return 4

        token_info = TOKEN_MANDATORY_LABEL()
        resize(token_info, info_size.value)
        if not GetTokenInformation(
                token,
                TokenIntegrityLevel,
                byref(token_info),
                info_size,
                byref(info_size)):
            logging.error(
                    'GetTokenInformation(): Unknown error with buffer size %d: %d', info_size.value, GetLastError())
            return 6

        p_sid_size = GetSidSubAuthorityCount(token_info.Label.Sid)
        res = GetSidSubAuthority(token_info.Label.Sid, p_sid_size.contents.value - 1)
        value = res.contents.value
        return mapping.get(value) or u'0x%04x' % value

    finally:
        CloseHandle(token)
