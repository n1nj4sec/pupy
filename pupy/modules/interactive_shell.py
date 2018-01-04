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
import rpyc

from modules.lib.utils.cmdrepl import CmdRepl

__class_name__="InteractiveShell"
@config(cat="admin")
class InteractiveShell(PupyModule):
    """
        open an interactive command shell with a nice tty
    """
    max_clients=1
    pipe = None
    complete = Event()
    rec = 'ttyrec'

    dependencies = {
        'windows': [ 'winpty.dll', 'winpty' ],
        'all': [ 'ptyshell' ],
    }

    def __init__(self, *args, **kwargs):
        PupyModule.__init__(self,*args, **kwargs)
        self.set_pty_size=None

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(description=self.__doc__)
        self.arg_parser.add_argument('-c', '--codepage', help="Decode output with encoding")
        self.arg_parser.add_argument('-T', action='store_true', dest='pseudo_tty', help="Disable tty allocation")
        self.arg_parser.add_argument('-S', '--su', help='Try to change uid (linux only)')
        self.arg_parser.add_argument('-R', default='ttyrec', dest='recorder',
                                         choices=['ttyrec', 'asciinema', 'none'],
                                         help="Change tty recorder")
        self.arg_parser.add_argument('program', nargs='?', help="open a specific program. Default for windows is cmd.exe and for linux it depends on the remote SHELL env var")

    def init(self, cmdline, args):
        if args.pseudo_tty or args.recorder == 'none':
            self.rec = None
        else:
            self.rec = args.recorder

        PupyModule.init(self, cmdline, args)

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

    def _remote_read(self, data):
        if not self.complete.is_set():
            self.stdout.write(data)
            self.stdout.flush()

    def run(self, args):
        if 'linux' in sys.platform and not args.pseudo_tty:
            try:
                fd = sys.stdin.fileno()
                old_settings = termios.tcgetattr(fd)
                tty.setraw(fd)
                self.raw_pty(args)
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        else:
            # Well, this probably doesn't work at all
            self.repl(args)

    def repl(self, args):
        self.client.load_package('pupyutils.safepopen')
        encoding=None
        program = [ "/bin/sh", "-i" ]
        if self.client.is_android():
            program = [ "/system/bin/sh" ]
        elif self.client.is_windows():
            program = [ 'cmd.exe', '/Q' ]
        if args.program:
            program = [ args.program ]

        self.pipe = self.client.conn.modules['pupyutils.safepopen'].SafePopen(
            program,
            interactive=True,
        )

        self.stdout.write('\r\nREPL started. Ctrl-C will the module \r\n')

        if self.client.is_windows():
            crlf = True
            interpreter = 'cmd.exe'
        else:
            crlf = False
            interpreter = 'sh'

        repl, _ = CmdRepl.thread(
            self.stdout,
            self.pipe.write,
            self.complete,
            crlf, interpreter,
            args.codepage
        )

        self.pipe.execute(self.complete.set, repl._con_write)

        self.complete.wait()
        self.pipe.terminate()

        # Well, there is no way to break upper thread without
        # new 100500 threads which will wrap stdin, poll each other...
        # Just press the fucked enter to avoid this crap

        self.stdout.write('\r\nPress Enter to close to REPL\r\n')

    def raw_pty(self, args):
        ps = self.client.conn.modules['ptyshell'].PtyShell()
        program = None

        if args.program:
            program=args.program.split()

        old_handler = None

        self.client.conn.register_remote_cleanup(ps.close)

        try:
            term = os.environ.get('TERM', 'xterm')

            ps.spawn(program, term=term, suid=args.su)

            self.set_pty_size=rpyc.async(ps.set_pty_size)
            old_handler = pupylib.PupySignalHandler.set_signal_winch(self._signal_winch)
            self._signal_winch(None, None) # set the remote tty sie to the current terminal size

            self.complete = Event()
            ps.start_read_loop(self._remote_read, self.complete.set)
            self._start_read_loop(ps.write)

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

    def interrupt(self):
        if self.complete:
            self.complete.set()
