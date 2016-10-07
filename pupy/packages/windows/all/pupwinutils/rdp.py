from _winreg import *
import ctypes
import subprocess

def check_if_admin():
	return ctypes.windll.shell32.IsUserAnAdmin() != 0

def setRegValue(aReg, keyPath, regPath, value):
	try:
		aKey = OpenKey(aReg, keyPath, 0, KEY_WRITE)
		SetValueEx(aKey, regPath, 0, REG_DWORD, value)
		CloseKey(aKey)
		return True
	except:
		return False

def modifyKey(keyPath, regPath, value, root=HKEY_LOCAL_MACHINE):
	aReg = ConnectRegistry(None, root)

	if not setRegValue(aReg, keyPath, regPath, value):
		CloseKey(aReg)
		return False

	CloseKey(aReg)
	return True

def executeCmd(cmd):
	command=['cmd.exe', '/c'] + cmd.split()
	res = subprocess.check_output(command, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, universal_newlines=True)
	# info=subprocess.STARTUPINFO()
	# info.dwFlags=subprocess.STARTF_USESHOWWINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
	# info.wShowWindow=subprocess.SW_HIDE
	# p=subprocess.Popen(command, startupinfo=info, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, universal_newlines=True)
	# results, _=p.communicate()
	return res

def enable_rdp():
	# enable RDP 
	if modifyKey(r"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\", 'fDenyTSConnections', 0):
		# disable NLA authentication
		if modifyKey(r"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\", "UserAuthentication", 0):
			# adding a firewall rule
			cmd = 'netsh firewall set service type=remotedesktop mod=enable'
			# cmd = 'netsh advfirewall firewall set rule group="Bureau à distance" new enable=Yes'
			r = executeCmd(cmd)
			if 'ok' in r.lower():
				print '[+] RDP enabled'
			else:
				print '[-] Failed to add new firewall rule'
		else:
			print '[-] Failed to disable NLA authentication'
	else:
		print '[-] Failed to change the rdp key'


def disable_rdp():
	# disable RDP 
	if modifyKey(r"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\", 'fDenyTSConnections', 1):
		# enable NLA authentication
		if modifyKey(r"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\", "UserAuthentication", 1):
			# removing a firewall rule
			cmd = 'netsh firewall set service type=remotedesktop mod=disable'
			r = executeCmd(cmd)
			if 'ok' in r.lower():
				print '[+] RDP disabled'
			else:
				print '[-] Failed to remove the rdp firewall rule'
		else:
			print '[-] Failed to disable NLA authentication'
	else:
		print '[-] Failed to change the rdp key'



# www.vladan.fr/multiple-rdp-sessions-on-windows/
