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
from ctypes import *

LPVOID = c_void_p
HANDLE	 = LPVOID
INVALID_HANDLE_VALUE = c_void_p(-1).value
DWORD = c_uint32
LONG= c_long

class LUID(Structure):
	_fields_ = [
		("LowPart",	 DWORD),
		("HighPart",	LONG),
	]
class LUID_AND_ATTRIBUTES(Structure):
	_fields_ = [
		("Luid",		LUID),
		("Attributes", DWORD),
	]

class TOKEN_PRIVILEGES(Structure):
	_fields_ = [
		("PrivilegeCount", DWORD),
		("Privileges",	 LUID_AND_ATTRIBUTES),
	]

def EnablePrivilege(privilegeStr, hToken = None):
	"""Enable Privilege on token, if no token is given the function gets the token of the current process."""
	close=False
	if hToken == None:
		close=True
		TOKEN_ADJUST_PRIVILEGES = 0x00000020
		TOKEN_QUERY = 0x0008
		hToken = HANDLE(INVALID_HANDLE_VALUE)
		res=windll.advapi32.OpenProcessToken( windll.kernel32.GetCurrentProcess(), (TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY), byref(hToken) )
  
	privilege_id = LUID()
	res=windll.advapi32.LookupPrivilegeValueA(None, privilegeStr, byref(privilege_id))

	SE_PRIVILEGE_ENABLED = 0x00000002
	laa = LUID_AND_ATTRIBUTES(privilege_id, SE_PRIVILEGE_ENABLED)
	tp = TOKEN_PRIVILEGES(1, laa)

	ERROR_NOT_ALL_ASSIGNED=1300

	res=windll.advapi32.AdjustTokenPrivileges(hToken, False, byref(tp), sizeof(tp), None, None)
	if not res:
		raise WinError()
	else:
		res=windll.kernel32.GetLastError()
		if res!=0:
			raise WinError()
	if close:
		windll.kernel32.CloseHandle(hToken)


