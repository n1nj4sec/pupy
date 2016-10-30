# -*- coding: utf-8 -*-

import rpyc
import winpty
import threading

class PtyShell(object):
    def __init__(self):
        self.pty = None

    def close(self):
        if self.pty:
            self.pty.close()

    def __del__(self):
        self.close()

    def spawn(self, argv=None, term=None):
        if self.pty:
            return

        if not argv:
            argv = r'C:\windows\system32\cmd.exe'

        self.pty = winpty.WinPTY(argv)

    def write(self, data):
        if not self.pty:
            return

        self.pty.write(data)

    def set_pty_size(self, ws_row, ws_col, ws_xpixel, ws_ypixel):
        if not self.pty:
            return

        self.pty.resize(ws_row, ws_col)

    def start_read_loop(self, print_callback, close_callback):
        if not self.pty:
            return

        t=threading.Thread(
            target=self._read_loop,
            args=(print_callback, close_callback)
        )

        t.daemon=True
        t.start()

    def _read_loop(self, print_callback, close_callback):
        cb = rpyc.async(print_callback)
        close_cb = rpyc.async(close_callback)

        while True:
            data = self.pty.read()
            if not data:
                break

            cb(data)

        close_cb()

    def close(self):
        if not self.pty:
            return

        self.pty.close()
