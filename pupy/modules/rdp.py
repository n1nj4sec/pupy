# -*- coding: utf-8 -*-

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from threading import Event

__class_name__="Rdp"

@config(cat="admin", compatibilities=['windows', 'linux', 'darwin'])
class Rdp(PupyModule):
    """ Enable / Disable rdp connection or check for valid credentials on a remote host """

    dependencies = {
        'windows': ['pupwinutils.rdp'],
        'all': [
            'pupyutils.rdp_check', 'impacket', 'calendar', 'OpenSSL'
        ]
    }

    terminate_scan = None
    terminate_wait = None
    terminated = False

    @classmethod
    def init_argparse(cls):

        example = 'Examples:\n'
        example += '>> run rdp local --enable\n'
        example += '>> run rdp local --disable\n'
        example += '>> run rdp remote -u john -p P4ssw0rd 192.168.0.1,192.168.1.2,192.168.3.0/24\n'

        cls.arg_parser = PupyArgumentParser(prog="Rdp", description=cls.__doc__, epilog=example)
        subparsers = cls.arg_parser.add_subparsers(title='Choose a specific action')

        local = subparsers.add_parser('local', help='Enable / Disable rdp connection (only for windows hosts)')
        local.set_defaults(local=True, remote=False)
        local.add_argument('--enable', '-e', action='store_true', help='enable rdp')
        local.add_argument('--disable', '-d', action='store_true', help='disable rdp')

        remote = subparsers.add_parser('remote', help='Check for valid credentials on a remote host')
        remote.set_defaults(remote=True, local=False)

        remote.add_argument('-d', dest='domain', default='workgroup', help='domain used for checking RDP connection')
        remote.add_argument('-u', dest='username', required=True, help='username used for checking RDP connection')
        remote.add_argument('-p', dest='password', default= '', help='password used for checking RDP connection')
        remote.add_argument('-H', dest='hashes', help='NTLM hashes used for checking RDP connection')

        remote.add_argument('targets', help='remote host or range for checking RDP connection')

    def run(self, args):
        # TO DO: enable multi RDP session, see MIMIKATZ for example

        if args.local:
            if args.enable or args.disable:
                if not self.client.is_windows():
                    self.error("This option could be used only on windows hosts")
                    return

                check_if_admin = self.client.remote('pupwinutils.rdp', 'check_if_admin', False)
                disable_rdp = self.client.remote('pupwinutils.rdp', 'disable_rdp', False)
                enable_rdp = self.client.remote('pupwinutils.rdp', 'enable_rdp', False)

                # check if admin
                if not check_if_admin:
                    self.error("Admin privileges are required")
                    return

                if args.disable:
                    disable_rdp()

                if args.enable:
                    enable_rdp()

        elif args.remote:
            check_rdp = self.client.remote('pupyutils.rdp_check', 'check_rdp', False)

            self.terminate_wait = Event()

            def show_result(host, result):
                if result is True:
                    self.success('{}: OK'.format(host))
                elif result is False:
                    self.warning('{}: FAIL'.format(host))
                else:
                    self.error('{}: {}'.format(host, result))

            def on_complete(hosts):
                self.success('Completed ({} connectable hosts)'.format(len(hosts)))
                self.terminate_wait.set()

            self.terminate_scan = check_rdp(
                args.targets, args.username, args.password, args.domain, args.hashes,
                on_complete, show_result
            )

            self.terminate_wait.wait()

    def interrupt(self):
        if not self.terminated:
            self.terminated = True

            if self.terminate_scan:
                self.terminate_scan()

            if self.terminate_wait:
                self.terminate_wait.set()
