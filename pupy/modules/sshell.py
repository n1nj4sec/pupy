# -*- coding: utf-8 -*-

import sys
import rpyc

from urlparse import urlparse
from argparse import REMAINDER

from os import path, environ, walk

from pupylib.PupyCompleter import path_completer
from pupylib.PupyModule import (
    config, PupyModule, PupyArgumentParser,
    REQUIRE_TERMINAL
)

__class_name__="SSHell"
@config(cat='admin')
class SSHell(PupyModule):
    """
        Interactive SSH shell
    """

    rec = 'ttyrec'

    io = REQUIRE_TERMINAL

    dependencies = [
        'paramiko', 'cryptography', 'ecdsa', 'ssh'
    ]

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(description=cls.__doc__)
        cls.arg_parser.add_argument('-T', '--timeout',
                                    type=int, default=30, help='Set communication timeout (default 30s)')
        cls.arg_parser.add_argument('-R', default='asciinema', dest='recorder',
                                         choices=['ttyrec', 'asciinema', 'asciinema1', 'none'],
                                         help="Change tty recorder")
        cls.arg_parser.add_argument('-u', '--user', help='Use user name')
        cls.arg_parser.add_argument('-p', '--port', type=int, help='Use port')
        cls.arg_parser.add_argument('-P', '--passwords',
                                    action='append', default=[],
                                    help='Use SSH auth password (can specify many times)')
        cls.arg_parser.add_argument('-KP', '--key-passwords',
                                    action='append', default=[],
                                    help='Use SSH key password (can specify many times)')
        cls.arg_parser.add_argument('-k', '--private-keys', help='Use private keys (Use "," as path separator)',
                                    completer=path_completer)
        cls.arg_parser.add_argument('host', help='host to connect')
        cls.arg_parser.add_argument('program', nargs=REMAINDER, help='Execute in remote SSH session shell')

    def init(self, args):
        if args.recorder == 'none':
            self.rec = None
        else:
            self.rec = args.recorder

        PupyModule.init(self, args)

    def run(self, args):
        if 'linux' not in sys.platform:
            raise NotImplementedError('Interactive shell is not supported for this platform')

        # Hooks

        # self.stdout may be mapped to self.iogroup.stdout via logger
        # TODO: Logger refactoring - migrate to IOGroup?

        term = environ.get('TERM', 'xterm')

        ssh_interactive = self.client.remote('ssh', 'ssh_interactive', False)

        h, w, hp, wp = self.iogroup.window_size

        host = args.host

        if '://' not in host:
            host = 'ssh://' + host

        uri = urlparse(host)
        host = uri.hostname
        port = args.port or uri.port or 22
        user = args.user or uri.username
        u_pwd = [uri.password] if uri.password else []
        passwords = (args.passwords or tuple(u_pwd),
                    tuple(args.key_passwords))
        program = ' '.join(args.program) or None

        exit_status = [-1]

        private_keys = None
        if args.private_keys:
            private_keys = tuple(list(self._find_private_keys(args.private_keys)))

        def write(data):
            if not self.iogroup.closed:
                self.stdout.write(data)

        def local_close(iogroup):
            iogroup.close()

        def remote_close(remote_exit_status):
            exit_status[0] = remote_exit_status
            self.iogroup.close()

        try:
            attach, writer, resizer, closer = ssh_interactive(
                term, w, h, wp, hp,
                host, port, user, passwords, private_keys,
                program, write, remote_close, args.timeout
            )

        except Exception, e:
            self.error(e.args[0])
            return

        self.client.conn.register_remote_cleanup(closer)

        remote_write = rpyc.async(writer)

        self.iogroup.set_on_winch(rpyc.async(resizer))
        self.iogroup.set_mapping('~~~.', local_close)

        with self.iogroup:
            attach()

            for data in self.iogroup:
                remote_write(data)

        self.client.conn.unregister_remote_cleanup(closer)
        closer()

        if exit_status[0] == 0:
            self.success('SSH closed')
        else:
            self.error('SSH closed ({})'.format(exit_status[0]))

    def _find_private_keys(self, fpath):
        if path.isfile(fpath):
            try:
                with open(fpath) as content:
                    yield content.read()

            except OSError:
                pass

            return

        for root, dirs, files in walk(fpath):
            for sfile in files:
                try:
                    sfile_path = path.join(root, sfile)
                    with open(sfile_path) as content:
                        first_line = content.readline(256)
                        if 'PRIVATE KEY-----' in first_line:
                            yield first_line + content.read()

                except (OSError, IOError):
                    pass
