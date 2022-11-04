# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
import sys
import os
from pupy.network.lib.rpc import nowait
from argparse import REMAINDER

from pupy.pupylib.PupyModule import (
    config, PupyModule, PupyArgumentParser,
    REQUIRE_TERMINAL
)

__class_name__="InteractiveShell"
@config(cat="admin")
class InteractiveShell(PupyModule):
    """
        open an interactive command shell with a nice tty
    """

    rec = 'ttyrec'

    io = REQUIRE_TERMINAL

    dependencies = {
        'windows': ['winpty.dll', 'winpty', 'pupwinutils.security'],
        'all': ['ptyshell'],
    }

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(description=cls.__doc__)
        cls.arg_parser.add_argument('-c', '--codepage', help="Decode output with encoding")
        cls.arg_parser.add_argument('-T', action='store_true', dest='pseudo_tty', help="Disable tty allocation")
        cls.arg_parser.add_argument('-S', '--su', help='Try to change uid (linux only)')
        cls.arg_parser.add_argument('-R', default='asciinema', dest='recorder',
                                         choices=['ttyrec', 'asciinema', 'asciinema1', 'none'],
                                         help="Change tty recorder")
        cls.arg_parser.add_argument('program', nargs=REMAINDER, help='Execute in shell')

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

        ps = None
        detached = [False]

        def write(data):
            if not self.iogroup.closed:
                self.stdout.write(data)

        def local_detach(iogroup):
            detached[0] = True
            iogroup.close()

        def local_close(iogroup):
            iogroup.close()

        term = os.environ.get('TERM', 'xterm')

        acquire_shell = self.client.remote('ptyshell', 'acquire', False)
        release_shell = self.client.remote('ptyshell', 'release', False)

        cmdline = ' '.join(args.program)

        try:
            new, ps = acquire_shell(cmdline, term, args.su)
        except Exception as e:
            self.error(' '.join(x for x in e.args if type(x) == str))
            return

        if not ps:
            self.error('Can\'t create shell')
            return

        if new:
            self.client.conn.register_remote_cleanup(release_shell)

        remote_write = nowait(ps.write)

        self.iogroup.set_on_winch(nowait(ps.set_pty_size))
        self.iogroup.set_mapping('~~~.', local_close)
        self.iogroup.set_mapping('~~~,', local_detach)

        if new:
            self.success('Start new shell')
        else:
            self.warning('Reuse previous shell')

        with self.iogroup:
            ps.attach(write, self.iogroup.close)

            for data in self.iogroup:
                remote_write(data)

        try:
            ps.detach()
        except Exception as e:
            detached[0] = False
            self.error(e)

        if detached[0]:
            self.warning('Shell detached')
        else:
            try:
                release_shell()
                self.success('Shell closed')
                self.client.conn.unregister_remote_cleanup(release_shell)
            except Exception as e:
                self.error(e)
