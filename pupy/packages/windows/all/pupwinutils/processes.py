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
from ctypes import byref, c_bool
from ctypes import windll
import psutil
import platform
import subprocess

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MAX_PATH=260

def is_process_64(pid):
	""" Take a pid. return True if process is 64 bits, and False otherwise. """
	is64=False
	if not "64" in platform.machine():
		return False
	hProcess = windll.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
	is64=is_process_64_from_handle(hProcess)
	windll.kernel32.CloseHandle(hProcess)
	return is64

def is_process_64_from_handle(hProcess):
	""" Take a process handle. return True if process is 64 bits, and False otherwise. """
	iswow64 = c_bool(False)
	if not hasattr(windll.kernel32,'IsWow64Process'):
		return False
	windll.kernel32.IsWow64Process(hProcess, byref(iswow64))
	return not iswow64.value
	
def enum_processes():
	proclist=[]
	for proc in psutil.process_iter():
		try:
			pinfo = proc.as_dict(attrs=['username', 'pid', 'name', 'exe', 'cmdline', 'status'])
			pinfo['arch']=("x64" if is_process_64(int(pinfo['pid'])) else "x32")
			proclist.append(pinfo)
		except psutil.NoSuchProcess:
			pass
	return proclist

def start_hidden_process(path):
	info = subprocess.STARTUPINFO()
	info.dwFlags = subprocess.STARTF_USESHOWWINDOW|subprocess.CREATE_NEW_PROCESS_GROUP
	info.wShowWindow = subprocess.SW_HIDE
	p=subprocess.Popen(path, startupinfo=info)
	return p


if __name__ == '__main__':
	for dic in enum_processes():
		print dic
