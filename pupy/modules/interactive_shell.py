# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

from pupylib.PupyModule import *
from pupylib.utils.rpyc_utils import redirected_stdio
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
from threading import Event
import rpyc

__class_name__="InteractiveShell"
def print_callback(data):
    os.write(sys.stdin.fileno(), data)

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

            fd=sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)

            self.ps=self.client.conn.modules['ptyshell'].PtyShell()
            program=None
            if args.program:
                program=args.program.split()
            try:
                term="xterm"
                if "TERM" in os.environ:
                    term=os.environ["TERM"]
                self.ps.spawn(program, term=term)
                is_closed=Event()
                self.ps.start_read_loop(print_callback, is_closed.set)
                self.set_pty_size=rpyc.async(self.ps.set_pty_size)
                old_handler = pupylib.PupySignalHandler.set_signal_winch(self._signal_winch)
                self._signal_winch(None, None) # set the remote tty sie to the current terminal size
                try:
                    tty.setraw(fd)
                    buf=b''
                    while True:
                        r, w, x = select.select([sys.stdin], [], [], 0.01)
                        if sys.stdin in r:
                            ch = os.read(fd, 1)
                            buf += ch
                        elif buf:
                            self.ps.write(buf)
                            buf=b''
                        elif is_closed.is_set():
                            break
                finally:
                    termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
                    pupylib.PupySignalHandler.set_signal_winch(old_handler)
            finally:
                try:
                    self.ps.close()
                except Exception:
                    pass
                self.set_pty_size=None
