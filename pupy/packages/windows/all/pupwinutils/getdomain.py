from _winreg import *

def get_domain_controller():

	aReg = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
	keypath = r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\History\\"
	subkey_name = 'DCName'
	try:
		aKey = OpenKey(aReg, keypath)
		val, _ = QueryValueEx(aKey, subkey_name)
		CloseKey(aKey)
		return val
	except:
		return False
