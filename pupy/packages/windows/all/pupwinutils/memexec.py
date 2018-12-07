# -*- coding: utf-8 -*-
# --------------------------------------------------------------
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors
# may be used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE
# --------------------------------------------------------------

import pupymemexec
import ctypes
import threading
import rpyc

from ctypes.wintypes import DWORD, HANDLE, BOOL, LPVOID, UINT
from ctypes import byref, create_string_buffer, POINTER, WinError

ERROR_BROKEN_PIPE = 0x6D

PVOID = ctypes.c_voidp
PDWORD = POINTER(DWORD)

GetLastError = ctypes.windll.kernel32.GetLastError

ReadFile = ctypes.windll.kernel32.ReadFile
ReadFile.restype = BOOL
ReadFile.argtypes = [
    HANDLE, LPVOID, DWORD, PVOID, PVOID
]

WriteFile = ctypes.windll.kernel32.WriteFile
WriteFile.restype = BOOL
WriteFile.argtypes = [
    HANDLE, LPVOID, DWORD, PVOID, PVOID
]

CloseHandle = ctypes.windll.kernel32.CloseHandle
CloseHandle.restype = BOOL
CloseHandle.argtypes = [HANDLE]

TerminateProcess = ctypes.windll.kernel32.TerminateProcess
TerminateProcess.restype = BOOL
TerminateProcess.argtypes = [HANDLE, UINT]

GetProcessId = ctypes.windll.kernel32.GetProcessId
GetProcessId.restype = DWORD
GetProcessId.argtypes = [HANDLE]

PIPE_READMODE_BYTE = 0x0
PIPE_NOWAIT = 0x1

class MemoryPE(object):
    ''' run a pe from memory. '''
    def __init__(self, raw_pe, args=[], suspended_process=None, hidden=True, dupHandle=None):
        self.cmdline = suspended_process or 'cmd.exe'

        if args:
            self.cmdline += ' '+' '.join(args)

        self.raw_pe = raw_pe
        self.suspended_process = suspended_process

        self.hidden = hidden

        self.hProcess = None
        self.pStdin = None
        self.pStdout = None
        self.complete_cb = None
        self.write_cb = None
        self.terminate = False

        self.dupHandle = dupHandle
        if self.dupHandle is None:
            self.dupHandle = 0

        self.EOF = threading.Event()
        self.stdout = ''

    def close(self):
        # Killing the program if he is still alive
        self.EOF.set()

        if self.pStdout:
            CloseHandle(self.pStdout)
            self.pStdout = None

        if self.pStdin:
            CloseHandle(self.pStdin)
            self.pStdin = None

        if self.hProcess:
            if self.terminate:
                TerminateProcess(self.hProcess, 1)

            CloseHandle(self.hProcess)
            self.hProcess = None

        if self.complete_cb:
            self.complete_cb()
            self.complete_cb = None

        if self.write_cb:
            self.write_cb = None

    def execute(self, complete_cb, write_cb=True):
        ''' Execute process '''

        if complete_cb:
            self.complete_cb = rpyc.async(complete_cb)

        if write_cb and write_cb is not True:
            self.write_cb = rpyc.async(write_cb)
            self.terminate = True

        try:
            hProcess, pStdin, pStdout = pupymemexec.run_pe_from_memory(
                self.cmdline, self.raw_pe, write_cb is not None,
                self.hidden, self.dupHandle
            )
        except Exception, e:
            self.write_cb('[!] memexec failed: {}\n'.format(e))
            return False

        self.pStdout = HANDLE(pStdout)
        self.pStdin = HANDLE(pStdin)

        self.hProcess = HANDLE(hProcess)

        if self.hProcess is None:
            return

        if write_cb:
            loop = threading.Thread(target=self._loop)
            loop.daemon = True
            loop.start()
        else:
            if self.complete_cb:
                self.complete_cb()

        return GetProcessId(self.hProcess)

    def _loop(self):
        try:
            while True:
                buffer = create_string_buffer(2048)
                c_read = DWORD(0)
                success = ReadFile(
                    self.pStdout, buffer, len(buffer)-1, byref(c_read), None
                )

                if not success:
                    last_error = GetLastError()
                    if last_error == ERROR_BROKEN_PIPE:
                        break

                if c_read.value > 0:
                    buffer[c_read.value] = '\x00'

                    if self.write_cb:
                        try:
                            self.write_cb(buffer.value)
                        except:
                            # We need to empty pipe anyway
                            pass
                    else:
                        self.stdout += buffer.value

        except Exception, e:
            if self.write_cb:
                try:
                    self.write_cb('[+] Exception: {}'.format(e))
                except:
                    pass

        finally:
            self.close()

    def write(self, data):
        try:
            c_written = DWORD()
            buffer = create_string_buffer(data)
            if not WriteFile(self.pStdin, buffer, len(buffer), byref(c_written), None):
                raise WinError()

        except:
            self.close()
