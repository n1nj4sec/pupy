# -*- coding: UTF8 -*-
from pupylib.PupyModule import *
from pupylib.utils.rpyc_utils import redirected_stdio
from netaddr import *

__class_name__="Rdp"

@config(cat="admin", compat="windows")
class Rdp(PupyModule):
    """ Enable / Disable rdp connection or check for valid credentials on a remote host """

    def init_argparse(self):

        example = 'Examples:\n'
        example += '>> run rdp local --enable\n'
        example += '>> run rdp local --disable\n'
        example += '>> run rdp remote -u john -p P4ssw0rd -t 192.168.0.1\n'
        example += '>> run rdp remote -u john -p P4ssw0rd -t 192.168.0.1/24\n'

        self.arg_parser = PupyArgumentParser(prog="Rdp", description=self.__doc__, epilog=example)
        subparsers = self.arg_parser.add_subparsers(title='Choose a specific action')

        local = subparsers.add_parser('local', help='Enable / Disable rdp connection (only for windows hosts)')
        local.set_defaults(local=True, remote=False)
        local.add_argument('--enable', '-e', action='store_true', help='enable rdp')
        local.add_argument('--disable', '-d', action='store_true', help='disable rdp')

        remote = subparsers.add_parser('remote', help='Check for valid credentials on a remote host')
        remote.set_defaults(remote=True, local=False)
        remote.add_argument('--target', '-t', dest='target', required=True, help='remote host or range for checking RDP connection')
        remote.add_argument('-d', dest='domain', default='workgroup', help='domain used for checking RDP connection')
        remote.add_argument('-u', dest='username', required=True, help='username used for checking RDP connection')
        remote.add_argument('-p', dest='password', default= '', help='password used for checking RDP connection')
        remote.add_argument('-H', dest='hashes', help='NTLM hashes used for checking RDP connection')

    def run(self, args):
        
        # TO DO: enable multi RDP session, see MIMIKATZ for example

        if args.local:
            if args.enable or args.disable:
                if not self.client.is_windows():
                    self.error("This option could be used only on windows hosts")
                    return
                
                self.client.load_package("pupwinutils.rdp")
                
                # check if admin
                if not self.client.conn.modules["pupwinutils.rdp"].check_if_admin():
                    self.error("Admin privileges are required")

                with redirected_stdio(self.client.conn):
                    if args.enable:
                        self.client.conn.modules["pupwinutils.rdp"].enable_rdp()

                    if args.disable:
                        self.client.conn.modules["pupwinutils.rdp"].disable_rdp()

        elif args.remote:
            if "/" in args.target[0]:
                hosts = IPNetwork(args.target[0])
            else:
                hosts = list()
                hosts.append(args.target)

            self.client.load_package("pupyutils.rdp_check")
            self.client.load_package("impacket")
            self.client.load_package("calendar")
            self.client.load_package("OpenSSL")
            for host in hosts:
                with redirected_stdio(self.client.conn):
                    self.client.conn.modules["pupyutils.rdp_check"].check_rdp(host, args.username, args.password, args.domain, args.hashes)
