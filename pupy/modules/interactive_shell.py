# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

from pupylib.PupyModule import *
from pupylib.utils.rpyc_utils import redirected_stdio
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
import rpyc

__class_name__="InteractiveShell"
@config(cat="admin")
class InteractiveShell(PupyModule):
    """
        open an interactive command shell. tty are well handled for targets running *nix
    """
    max_clients=1

    def __init__(self, *args, **kwargs):
        PupyModule.__init__(self,*args, **kwargs)
        self.set_pty_size=None
    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(description=self.__doc__)
        self.arg_parser.add_argument('-T', action='store_true', dest='pseudo_tty', help="Disable tty allocation")
        self.arg_parser.add_argument('program', nargs='?', help="open a specific program. Default for windows is cmd.exe and for linux it depends on the remote SHELL env var")

    def _signal_winch(self, signum, frame):
        if self.set_pty_size is not None:
            buf = array.array('h', [0, 0, 0, 0])
            fcntl.ioctl(pty.STDOUT_FILENO, termios.TIOCGWINSZ, buf, True)
            self.set_pty_size(buf[0], buf[1], buf[2], buf[3])

    def _start_read_loop(self, write_cb, complete):
        t = Thread(
            target=self._read_loop, args=(write_cb, complete)
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

            buf.append(os.read(fd, 1))
        return b''.join(buf)

    def _read_loop(self, write_cb, complete):
        try:
            self._read_loop_base(write_cb, complete)
        except AsyncResultTimeout:
            pass
        finally:
            sys.stdout.write('\r\n')
            complete.set()


    def _read_loop_base(self, write_cb, complete):
        lastbuf = b''
        write_cb = rpyc.async(write_cb)

        while not complete.is_set():
            r, _, x = select.select([sys.stdin], [], [sys.stdin], None)
            if x:
                break

            if r:
                if not complete.is_set():
                    buf = self._read_stdin_non_block()
                    if lastbuf.startswith(b'\r'):
                        vbuf = lastbuf + buf
                        if vbuf.startswith(b'\r~'):
                            if len(vbuf) < 3:
                                lastbuf = vbuf
                                continue
                            elif vbuf.startswith(b'\r~.'):
                                break
                            elif vbuf.startswith(b'\r~,'):
                                self.client.conn._conn.ping(timeout=1)
                                buf = buf[3:]
                                if not buf:
                                    continue

                    write_cb(buf)
                    lastbuf = buf

    def _remote_read(self, data, complete):
        if not complete.is_set():
            os.write(sys.stdout.fileno(), data)

    def run(self, args):
        if self.client.is_windows() or args.pseudo_tty:
            self.client.load_package("interactive_shell")
            encoding=None
            program="/bin/sh"
            if self.client.is_android():
                program="/system/bin/sh"
            elif self.client.is_windows():
                program="cmd.exe"
            if args.program:
                program=args.program
            with redirected_stdio(self.client.conn):
                self.client.conn.modules.interactive_shell.interactive_open(program=program)
        else: #handling tty
            self.client.load_package("ptyshell")

            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)

            ps = self.client.conn.modules['ptyshell'].PtyShell()
            program = None

            if args.program:
                program=args.program.split()

            try:
                term = os.environ.get('TERM', 'xterm')
                ps.spawn(program, term=term)

                closed = Event()

                self.set_pty_size=rpyc.async(ps.set_pty_size)
                old_handler = pupylib.PupySignalHandler.set_signal_winch(self._signal_winch)
                self._signal_winch(None, None) # set the remote tty sie to the current terminal size
                tty.setraw(fd)

                ps.start_read_loop(lambda data: self._remote_read(data, closed), closed.set)
                self._start_read_loop(ps.write, closed)

                closed.wait()

                # Read loop here

                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
                pupylib.PupySignalHandler.set_signal_winch(old_handler)

            finally:
                try:
                    self.ps.close()
                except Exception:
                    pass
                self.set_pty_size=None
