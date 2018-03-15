# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

from pupylib.PupyModule import *
from rpyc.core.async import AsyncResultTimeout
import sys
import os
if sys.platform!="win32":
    import termios
    import tty
    import pty
    import select
    import pupylib.PupySignalHandler
    import fcntl
    import array

import time
import StringIO
from threading import Event, Thread
from Queue import Queue
import rpyc

__class_name__="InteractiveShell"
@config(cat="admin")
class InteractiveShell(PupyModule):
    """
        open an interactive command shell with a nice tty
    """
    max_clients=1
    pipe = None
    rec = 'ttyrec'

    io = REQUIRE_TERMINAL

    dependencies = {
        'windows': [ 'winpty.dll', 'winpty' ],
        'all': [ 'ptyshell' ],
    }

    def __init__(self, *args, **kwargs):
        super(InteractiveShell, self).__init__(*args, **kwargs)

        self.set_pty_size = None
        self.read_queue = Queue()
        self.complete = Event()

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(description=cls.__doc__)
        cls.arg_parser.add_argument('-c', '--codepage', help="Decode output with encoding")
        cls.arg_parser.add_argument('-T', action='store_true', dest='pseudo_tty', help="Disable tty allocation")
        cls.arg_parser.add_argument('-S', '--su', help='Try to change uid (linux only)')
        cls.arg_parser.add_argument('-R', default='ttyrec', dest='recorder',
                                         choices=['ttyrec', 'asciinema', 'none'],
                                         help="Change tty recorder")
        cls.arg_parser.add_argument('program', nargs='?', help="open a specific program. Default for windows is cmd.exe and for linux it depends on the remote SHELL env var")

    def init(self, args):
        if args.pseudo_tty or args.recorder == 'none':
            self.rec = None
        else:
            self.rec = args.recorder

        PupyModule.init(self, args)

    def _signal_winch(self, signum, frame):
        if self.set_pty_size is not None:
            buf = array.array('h', [0, 0, 0, 0])
            fcntl.ioctl(pty.STDOUT_FILENO, termios.TIOCGWINSZ, buf, True)
            self.set_pty_size(buf[0], buf[1], buf[2], buf[3])

    def _start_read_loop(self, write_cb):
        t = Thread(
            target=self._read_loop, args=(write_cb,)
        )
        t.daemon = True
        t.start()

    def _start_render_loop(self):
        t = Thread(
            target=self._render_loop
        )
        t.daemon = True
        t.start()

    def _read_stdin_non_block(self):
        buf = []
        fd = sys.stdin.fileno()
        while True:
            r, _, _ = select.select([sys.stdin], [], [], 0)
            if not r:
                break

            buf_ = array.array('i', [0])

            if fcntl.ioctl(sys.stdin, termios.FIONREAD, buf_, 1) == -1:
                break

            if not buf_[0]:
                continue

            chars = os.read(fd, buf_[0])
            buf.append(chars)
        return b''.join(buf)

    def _read_loop(self, write_cb):
        try:
            self._read_loop_base(write_cb)
        except AsyncResultTimeout, ReferenceError:
            pass
        finally:
            if not self.complete.is_set():
                self.stdout.write('\r\n')
                self.complete.set()

    def _render_loop(self):
        while not self.complete.is_set():
            data = self.read_queue.get()
            if data is None:
                break

            self.stdout.write(data)
            self.stdout.flush()

    def _read_loop_base(self, write_cb):
        lastbuf = b''
        write_cb = rpyc.async(write_cb)

        while not self.complete.is_set():
            r, _, x = select.select([sys.stdin], [], [sys.stdin], None)
            if x:
                break

            if r:
                if not self.complete.is_set():
                    buf = self._read_stdin_non_block()
                    if lastbuf.startswith(b'\r'):
                        lastbuf += buf
                        if lastbuf.startswith(b'\r~'):
                            if len(lastbuf) < 3:
                                continue
                            elif lastbuf.startswith(b'\r~.'):
                                break
                            elif lastbuf.startswith(b'\r~,'):
                                self.client.conn._conn.ping(timeout=1)
                                buf = lastbuf[3:]
                                if not buf:
                                    continue

                    write_cb(buf)
                    lastbuf = buf

    def run(self, args):
        if not 'linux' in sys.platform:
            raise NotImplementedError('Interactive shell is not supported for this platform')

        try:
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            tty.setraw(fd)
            self.raw_pty(args)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

    def raw_pty(self, args):

        PtyShell = self.client.remote('ptyshell', 'PtyShell', False)

        ps = PtyShell()
        program = None

        if args.program:
            program = args.program.split()

        old_handler = None

        self.client.conn.register_remote_cleanup(ps.close)

        try:
            term = os.environ.get('TERM', 'xterm')

            ps.spawn(program, term=term, suid=args.su)

            self.set_pty_size=rpyc.async(ps.set_pty_size)
            old_handler = pupylib.PupySignalHandler.set_signal_winch(self._signal_winch)
            self._signal_winch(None, None) # set the remote tty sie to the current terminal size

            self.complete = Event()
            ps.start_read_loop(self.read_queue.put, self.complete.set)
            self._start_read_loop(ps.write)
            self._start_render_loop()

            self._signal_winch(None, None)

            self.complete.wait()

        finally:
            if old_handler:
                pupylib.PupySignalHandler.set_signal_winch(old_handler)

            try:
                self.ps.close()
            except Exception:
                pass

            try:
                self.client.conn.unregister_remote_cleanup(ps.close)
            except:
                pass

            self.set_pty_size=None
            self.complete.set()
            self.read_queue.put(None)

    def interrupt(self):
        if self.complete:
            self.complete.set()
