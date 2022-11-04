# -*- coding: utf-8 -*-

import ctypes
import sys

from ctypes import (
    cast, byref, windll
)

from ctypes.wintypes import (
    DWORD, LPCVOID, LPWSTR, LPVOID
)

kernel32 = windll.kernel32

LocalFree = kernel32.LocalFree
LocalFree.argtypes = (LPVOID,)

FormatMessageW = kernel32.FormatMessageW
FormatMessageW.restype = DWORD
FormatMessageW.argtypes = (
    DWORD, LPCVOID, DWORD, DWORD, LPWSTR,
    DWORD, LPVOID
)

FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x100
FORMAT_MESSAGE_FROM_SYSTEM = 0x1000

FORMAT_MESSAGE_FLAGS = \
    FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER


orig_FormatError = ctypes.FormatError


def FormatMessage(code):
    lpBuffer = LPWSTR()

    result = FormatMessageW(
        FORMAT_MESSAGE_FLAGS, None,
        DWORD(code),
        0x409,  # Always use English
        cast(byref(lpBuffer), LPWSTR),
        0, None
    )

    if not result:
        raise ctypes.WinError()

    msg = lpBuffer.value.rstrip()
    LocalFree(lpBuffer)

    # We can't use network.lib.convcompat at this point
    if sys.version_info.major < 3:
        msg = msg.encode('utf-8')

    return msg


def apply_winerror_hacks():
    setattr(ctypes, 'FormatError', FormatMessage)
