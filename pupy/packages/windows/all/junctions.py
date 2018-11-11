# -*- coding: utf-8 -*-
# https://eklausmeier.wordpress.com/2015/10/27/working-with-windows-junctions-in-python/

from ctypes import (
    WinDLL, POINTER, c_ubyte, Structure, addressof,
    Union, WinError, c_buffer, byref
)
from ctypes.wintypes import (
    DWORD, LPCWSTR, HANDLE, LPVOID, USHORT, ULONG,
    WCHAR, BOOL
)

import stat
import os

kernel32 = WinDLL('kernel32')
LPDWORD = POINTER(DWORD)
UCHAR = c_ubyte

GetFileAttributesW = kernel32.GetFileAttributesW
GetFileAttributesW.restype = DWORD
GetFileAttributesW.argtypes = (LPCWSTR,) #lpFileName In

INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF
FILE_ATTRIBUTE_REPARSE_POINT = 0x00400

CreateFileW = kernel32.CreateFileW
CreateFileW.restype = HANDLE
CreateFileW.argtypes = (LPCWSTR, #lpFileName In
                        DWORD,   #dwDesiredAccess In
                        DWORD,   #dwShareMode In
                        LPVOID,  #lpSecurityAttributes In_opt
                        DWORD,   #dwCreationDisposition In
                        DWORD,   #dwFlagsAndAttributes In
                        HANDLE)  #hTemplateFile In_opt

CloseHandle = kernel32.CloseHandle
CloseHandle.restype = BOOL
CloseHandle.argtypes = (HANDLE,) #hObject In

INVALID_HANDLE_VALUE = HANDLE(-1).value
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000

DeviceIoControl = kernel32.DeviceIoControl
DeviceIoControl.restype = BOOL
DeviceIoControl.argtypes = (HANDLE,  #hDevice In
                            DWORD,   #dwIoControlCode In
                            LPVOID,  #lpInBuffer In_opt
                            DWORD,   #nInBufferSize In
                            LPVOID,  #lpOutBuffer Out_opt
                            DWORD,   #nOutBufferSize In
                            LPDWORD, #lpBytesReturned Out_opt
                            LPVOID)  #lpOverlapped Inout_opt

FSCTL_GET_REPARSE_POINT = 0x000900A8
IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003
IO_REPARSE_TAG_SYMLINK = 0xA000000C
MAXIMUM_REPARSE_DATA_BUFFER_SIZE = 0x4000

class GENERIC_REPARSE_BUFFER(Structure):
    _fields_ = (('DataBuffer', UCHAR * 1),)


class SYMBOLIC_LINK_REPARSE_BUFFER(Structure):
    _fields_ = (('SubstituteNameOffset', USHORT),
                ('SubstituteNameLength', USHORT),
                ('PrintNameOffset', USHORT),
                ('PrintNameLength', USHORT),
                ('Flags', ULONG),
                ('PathBuffer', WCHAR * 1))

    @property
    def PrintName(self):
        arrayt = WCHAR * (self.PrintNameLength // 2)
        offset = type(self).PathBuffer.offset + self.PrintNameOffset
        return arrayt.from_address(addressof(self) + offset).value


class MOUNT_POINT_REPARSE_BUFFER(Structure):
    _fields_ = (('SubstituteNameOffset', USHORT),
                ('SubstituteNameLength', USHORT),
                ('PrintNameOffset', USHORT),
                ('PrintNameLength', USHORT),
                ('PathBuffer', WCHAR * 1))

    @property
    def PrintName(self):
        arrayt = WCHAR * (self.PrintNameLength // 2)
        offset = type(self).PathBuffer.offset + self.PrintNameOffset
        return arrayt.from_address(addressof(self) + offset).value


class REPARSE_DATA_BUFFER(Structure):
    class REPARSE_BUFFER(Union):
        _fields_ = (('SymbolicLinkReparseBuffer',
                        SYMBOLIC_LINK_REPARSE_BUFFER),
                    ('MountPointReparseBuffer',
                        MOUNT_POINT_REPARSE_BUFFER),
                    ('GenericReparseBuffer',
                        GENERIC_REPARSE_BUFFER))
    _fields_ = (('ReparseTag', ULONG),
                ('ReparseDataLength', USHORT),
                ('Reserved', USHORT),
                ('ReparseBuffer', REPARSE_BUFFER))
    _anonymous_ = ('ReparseBuffer',)


def islink(path):
    result = GetFileAttributesW(path)
    if result == INVALID_FILE_ATTRIBUTES:
        raise WinError()
    return bool(result & FILE_ATTRIBUTE_REPARSE_POINT)

def readlink(path):
    reparse_point_handle = CreateFileW(
        path,
        0,
        0,
        None,
        OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
        None)
    if reparse_point_handle == INVALID_HANDLE_VALUE:
        raise WinError()

    target_buffer = c_buffer(MAXIMUM_REPARSE_DATA_BUFFER_SIZE)
    n_bytes_returned = DWORD()
    io_result = DeviceIoControl(
        reparse_point_handle,
        FSCTL_GET_REPARSE_POINT,
        None, 0,
        target_buffer, len(target_buffer),
        byref(n_bytes_returned),
        None)

    CloseHandle(reparse_point_handle)
    if not io_result:
        raise WinError()

    rdb = REPARSE_DATA_BUFFER.from_buffer(target_buffer)
    if rdb.ReparseTag == IO_REPARSE_TAG_SYMLINK:
        return rdb.SymbolicLinkReparseBuffer.PrintName
    elif rdb.ReparseTag == IO_REPARSE_TAG_MOUNT_POINT:
        return rdb.MountPointReparseBuffer.PrintName

    raise ValueError("not a link")

class LinkStat(object):
    st_mode = stat.S_IFLNK
    st_uid = 0
    st_gid = 0
    st_size = 0
    st_mtime = 0
    st_rdev = 0

def lstat(path):
    try:
        is_link = islink(path)
    except WindowsError:
        is_link = False

    if is_link:
        return LinkStat()
    else:
        return os.stat(path)
