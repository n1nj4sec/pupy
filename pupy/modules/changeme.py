# -*- coding: utf-8 -*-
# Author: AlessandroZ

from pupylib import ROOT
from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.utils.credentials import Credentials
from pupylib.utils.changeme.load_creds import Credentials as changeme_creds

from netaddr import IPNetwork

import os
import re

__class_name__="Changeme"

@config(cat="creds", compat=["linux", "windows"])
class Changeme(PupyModule):
    """
        Default Credential Scanner
    """
    dependencies = {
        'all': [
            'OpenSSL',
            'ftplib', 'zipfile', 'telnetlib',
            '_LWPCookieJar', '_MozillaCookieJar', 'Cookie', 'cookielib',
            'cgi', 'mimetypes', 'email', 'logutils',
            'urllib3', 'requests',
            'xml','_elementtree', 'calendar', 'xml', 'xml.etree',
            'changeme'
        ]
    }


    @classmethod
    def init_argparse(cls):
        header = """
 #####################################################
#       _                                             #
#   ___| |__   __ _ _ __   __ _  ___ _ __ ___   ___   #
#  / __| '_ \ / _` | '_ \ / _` |/ _ \ '_ ` _ \ / _ \\  #
# | (__| | | | (_| | | | | (_| |  __/ | | | | |  __/  #
#  \___|_| |_|\__,_|_| |_|\__, |\___|_| |_| |_|\___|  #
#                         |___/                       #
#                                                     #
#  Default Credential Scanner                         #
 #####################################################
    """

        example = '''
Examples:
>> run changeme -c web --name tomcat --target 192.168.1.10
'''

        cls.arg_parser = PupyArgumentParser(prog="changeme", description=header + cls.__doc__, epilog=example)
        cls.arg_parser.add_argument('--protocol', choices=['ftp', 'http', 'mssql', 'ssh', 'telnet'], help='Protocol of default creds to scan for', default=None)
        cls.arg_parser.add_argument('--category', '-c', choices=['webcam', 'web', 'phone', 'printer'], help='Category of default creds to scan for', default=None)
        cls.arg_parser.add_argument('--name', '-n', type=str, help='Narrow testing to the supplied credential name', default=None)

        # Targets to launch scan
        cls.arg_parser.add_argument('--target', type=str, help='Subnet or IP to scan')
        cls.arg_parser.add_argument('--targets', type=str, help='File of targets to scan (IP or IP:PORT)', default=None)
        cls.arg_parser.add_argument('--port', type=int, help='Custom port to connect', default=None)
        cls.arg_parser.add_argument('--ssl', action='store_true', help='Use ssl', default=None)
        cls.arg_parser.add_argument('--creds', type=str, help='File of custom credentials to check (login/password)', default=None)

        # Log and output
        cls.arg_parser.add_argument('--proxy', '-p', type=str, help='HTTP(S) Proxy', default=None)
        cls.arg_parser.add_argument('--log', '-l', type=str, help='Write logs to logfile', default=None)
        # cls.arg_parser.add_argument('--output', '-o', type=str, help='Name of file to write CSV results', default=None)

        # Verbosity
        cls.arg_parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
        cls.arg_parser.add_argument('--debug', '-d', action='store_true', help='Debug output')

        # Advanced options
        cls.arg_parser.add_argument('--timeout', type=int, help='Timeout in seconds for a request, default=10', default=10)
        cls.arg_parser.add_argument('--useragent', '-ua', type=str, help="User agent string to use")
        cls.arg_parser.add_argument('--delay', '-dl', type=int, help="Specify a delay in milliseconds to avoid 429 status codes default=500", default=500)

    def run(self, args):

        proxy = None
        if args.proxy and re.match('^https?://[0-9\.]+:[0-9]{1,5}$', args.proxy):
            proxy = {
                'http': args.proxy,
                'https': args.proxy
            }
        elif args.proxy:
            print '[!] Invalid proxy, must be http(s)://x.x.x.x:8080'
            return

        custom_cred = None
        if args.creds:
            custom_cred = self.get_custom_creds(args.creds)
            if not custom_cred:
                return

        targets_list = self.build_targets_list(target=args.target, file=args.targets)
        if targets_list:
            # Load credential locally from filesystem
            root = os.path.join(ROOT, "external", "changeme")
            creds = changeme_creds().load_creds(root, args.protocol, args.name, args.category)
            # Run main function
            pwd_found = self.client.conn.modules["changeme.core"].run_changeme(
                protocol=args.protocol,
                category=args.category,
                name=args.name,
                targets=targets_list,
                port=args.port,
                ssl=args.ssl,
                proxy=proxy,
                log=args.log,
                verbose=args.verbose,
                debug=args.debug,
                timeout=args.timeout,
                useragent=args.useragent,
                delay=args.delay,
                creds=creds,
                custom_creds=custom_cred
            )

            if pwd_found:
                db = Credentials(client=self.client, config=self.config)

                clean_creds = []
                for pwd in pwd_found:
                    self.success('%s' % pwd['name'])
                    self.success('URL: %s' % pwd['url'])
                    self.success('%s/%s' % (pwd['username'], pwd['password']))

                    clean_cred = {}
                    clean_cred['Category'] = '%s' % pwd['name']
                    clean_cred['CredType'] = 'plaintext'
                    clean_cred['URL'] = pwd['url']
                    clean_cred['Login'] = pwd['username']
                    clean_cred['Password'] = pwd['password']
                    clean_creds.append(clean_cred)

                    print

                try:
                    db.add(clean_creds)
                    self.success("Passwords stored on the database")
                except Exception, e:
                    print e
            else:
                self.warning('passwords not found')
        else:
            self.error('target not defined')

    def get_custom_creds(self, file):
        if not os.path.isfile(file):
            self.error("file %s not found" % file)
            return False

        custom_creds = list()
        with open(file, 'r') as fin:
            for x in fin.readlines():
                username, password = x.strip('\n').split('/', 1)
                custom_creds.append(
                    {
                        'username': username,
                        'password': password
                    }
                )
        return custom_creds


    def build_targets_list(self, target, file):
        targets_list = list()
        if target:
            for ip in IPNetwork(target).iter_hosts():
                targets_list.append(ip)

        if file:
            if not os.path.isfile(file):
                self.error("file %s not found" % file)
                return False
            with open(file, 'r') as fin:
                targets_list = [x.strip('\n') for x in fin.readlines()]

        return targets_list
