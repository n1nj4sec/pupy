# -*- coding: utf-8 -*-

__all__ = ['acquire', 'release']

import rpyc
import winpty

from collections import deque
from pupy import manager, Task

class PtyShell(Task):
    __slots__ = (
        'pty', 'argv', 'term', 'suid',
        'read_cb', 'close_cb', '_buffer'
    )

    def __init__(self, manager, argv=None, term=None, suid=None):
        super(PtyShell, self).__init__(manager)

        self.pty = None

        self.argv = argv
        self.term = term
        self.suid = suid

        self.read_cb = None
        self.close_cb = None

        self._buffer = deque(maxlen=50)

    def write(self, data):
        if not self.pty:
            return

        self.pty.write(data)

    def set_pty_size(self, ws_row, ws_col, ws_xpixel, ws_ypixel):
        if not self.pty:
            return

        self.pty.resize(ws_row, ws_col)

    def attach(self, read_cb, close_cb):
        if self.active:
            self.read_cb = rpyc.async(read_cb)
            self.close_cb = rpyc.async(close_cb)

            if self._buffer:
                for item in self._buffer:
                    self.read_cb(item)
        else:
            close_cb()

    def detach(self):
        self.read_cb = None
        self.close_cb = None

    def task(self):

        argv = self.argv
        if not argv:
            argv = r'C:\windows\system32\cmd.exe'

        try:
            self.pty = winpty.WinPTY(argv)

            if self.pty:
                self._read_loop()

        finally:
            try:
                self.stop()
            except:
                pass

            try:
                if self.close_cb:
                    self.close_cb()
            except:
                pass

    def _read_loop(self):
        while self.active:
            data = self.pty.read()
            if not data:
                break

            self._buffer.append(data)

            if self.read_cb:
                self.read_cb(data)

    def stop(self):
        super(PtyShell, self).stop()
        self.close()

    def close(self):
        if not self.pty:
            return

        self.pty.close()
        self.pty = None


def acquire(argv=None, term=None, suid=None):
    shell = manager.get(PtyShell)

    new = False
    if not (shell and shell.active):
        shell = manager.create(
            PtyShell,
            argv, term, suid)

        new = True

    return new, shell

def release():
    manager.stop(PtyShell)
