# -*- coding: utf-8 -*-

__all__ = [
  'get_streams'
]

from sys import getfilesystemencoding

from ctypes import WinDLL, c_void_p, byref, Structure
from ctypes import c_longlong as LONGLONG
from ctypes.wintypes import (
    LPWSTR, DWORD, WCHAR, HANDLE, BOOL
)

kernel32 = WinDLL('kernel32')

class LARGE_INTEGER_UNION(Structure):
    _fields_ = [
        ("QuadPart", LONGLONG),
    ]

class WIN32_FIND_STREAM_DATA(Structure):
    _fields_ = [
        ("StreamSize", LARGE_INTEGER_UNION),
        ("cStreamName", WCHAR * (260+36+1)),
    ]

FindFirstStreamW = kernel32.FindFirstStreamW
FindFirstStreamW.argtypes = [
    LPWSTR, DWORD, c_void_p, DWORD
]
FindFirstStreamW.restype = HANDLE

FindNextStreamW = kernel32.FindNextStreamW
FindNextStreamW.argtypes = [
    HANDLE, c_void_p
]
FindNextStreamW.restype = BOOL

FindClose = kernel32.FindClose
FindClose.argtypes = [
    HANDLE
]

INVALID_HANDLE_VALUE = c_void_p(-1).value

def get_streams(filename):
    if type(filename) == str:
        filename = filename.decode(
            getfilesystemencoding())

    file_infos = WIN32_FIND_STREAM_DATA()

    streams = FindFirstStreamW(filename, 0, byref(file_infos), 0)
    if streams == INVALID_HANDLE_VALUE:
        return []

    stream_name = file_infos.cStreamName
    stream_list = list()

    if stream_name:
        if not stream_name.startswith('::'):
            stream_list.append(stream_name.split(':')[1])

        while FindNextStreamW(streams, byref(file_infos)):
            stream_name = file_infos.cStreamName
            if not stream_name.startswith('::'):
                stream_list.append(stream_name.split(':')[1])

    FindClose(streams)
    return stream_list
