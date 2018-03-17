# -*- coding: utf-8 -*-

import sys
import os
import rpyc

from pupylib.PupyModule import *

__class_name__="InteractiveShell"
@config(cat="admin")
class InteractiveShell(PupyModule):
    """
        open an interactive command shell with a nice tty
    """

    rec = 'ttyrec'

    io = REQUIRE_TERMINAL

    dependencies = {
        'windows': [ 'winpty.dll', 'winpty' ],
        'all': [ 'ptyshell' ],
    }

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(description=cls.__doc__)
        cls.arg_parser.add_argument('-c', '--codepage', help="Decode output with encoding")
        cls.arg_parser.add_argument('-T', action='store_true', dest='pseudo_tty', help="Disable tty allocation")
        cls.arg_parser.add_argument('-S', '--su', help='Try to change uid (linux only)')
        cls.arg_parser.add_argument('-R', default='ttyrec', dest='recorder',
                                         choices=['ttyrec', 'asciinema', 'none'],
                                         help="Change tty recorder")
        cls.arg_parser.add_argument('program', nargs='?', help='Execute in shell')

    def init(self, args):
        if args.recorder == 'none':
            self.rec = None
        else:
            self.rec = args.recorder

        PupyModule.init(self, args)

    def run(self, args):
        if not 'linux' in sys.platform:
            raise NotImplementedError('Interactive shell is not supported for this platform')

        PtyShell = self.client.remote('ptyshell', 'PtyShell', False)

        ps = PtyShell()
        program = None

        if args.program:
            program = args.program.split()

        self.client.conn.register_remote_cleanup(ps.close)

        term = os.environ.get('TERM', 'xterm')

        # Hooks

        # self.stdout may be mapped to self.iogroup.stdout via logger
        # TODO: Logger refactoring - migrate to IOGroup?
        def write(data):
            if not self.iogroup.closed:
                self.stdout.write(data)
                self.stdout.flush()

        def close(iogroup):
            iogroup.close()

        remote_write = rpyc.async(ps.write)

        self.iogroup.set_on_winch(rpyc.async(ps.set_pty_size))
        self.iogroup.set_mapping('~~~.', close)

        try:
            with self.iogroup:
                ps.spawn(program, term=term, suid=args.su)
                ps.start_read_loop(write, self.iogroup.close)

                for data in self.iogroup:
                    remote_write(data)

        finally:
            try:
                ps.close()
                self.client.conn.unregister_remote_cleanup(ps.close)
            except Exception, e:
                self.error(e)

    def interrupt(self):
        self.iogroup.close()
