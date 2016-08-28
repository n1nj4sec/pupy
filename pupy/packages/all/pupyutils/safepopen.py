# -*- coding: utf-8 -*-

import threading
import subprocess
import Queue
import rpyc

def read_pipe(queue, pipe, bufsize):
    completed = False
    returncode = None

    while not completed:
        try:
            returncode = pipe.poll()
            completed = returncode != None
        except Exception as e:
            print('Exception: {}'.format(e))
            continue

        try:
            data = pipe.stdout.read() \
              if completed else pipe.stdout.readline(bufsize)
        except Exception:
            returncode = pipe.poll()
            break

        queue.put(data)

    queue.put(returncode)

class SafePopen(object):
    def __init__(self, *popen_args, **popen_kwargs):
        self._popen_args = popen_args

        # Well, this is tricky. If I'll pass array, then
        # it will be RPyC netref, so when I'll try to start
        # Popen, internally it will be dereferenced. But.
        # For some reason somewhere some lock acquires. Maybe
        # on fucked pupysh side? And all stuck.
        # RPYC IS CRAZY SHIT! DO WE REALLY NEED IT?!!!1111

        self._popen_args = [
            str(args) if type(args) == str else [
                str(x) for x in args
            ] for args in self._popen_args
        ]

        self._popen_kwargs = dict(popen_kwargs)
        self._reader = None
        self._pipe = None
        self._bufsize = 8196
        self.returncode = None

        if hasattr(subprocess, 'STARTUPINFO'):
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            self._popen_kwargs.update({
                'startupinfo': startupinfo,
            })

    def _execute(self, read_cb, close_cb):
        if read_cb:
            read_cb = rpyc.async(read_cb)

        if close_cb:
            close_cb = rpyc.async(close_cb)

        returncode = None
        try:
            kwargs = self._popen_kwargs
            # Setup some required arguments
            kwargs.update({
                'stdout': subprocess.PIPE,
                'bufsize': self._bufsize,
            })

            self._pipe = subprocess.Popen(
                *self._popen_args,
                **kwargs
            )
        except OSError as e:
            if read_cb:
                read_cb("Error: {}".format(e.strerror))
            try:
                returncode = self._pipe.poll()
            except Exception:
                pass

            self.returncode = returncode if returncode != None else -e.errno
            if close_cb:
                close_cb()
                return

        queue = Queue.Queue()
        self._reader = threading.Thread(
            target=read_pipe,
            args=(queue, self._pipe, self._bufsize)
        )
        self._reader.start()

        while True:
            data = queue.get()

            if type(data) == int:
                self.returncode = data
                break
            elif data:
                if read_cb:
                    read_cb(data)

        if close_cb:
            close_cb()

    def execute(self, close_cb, read_cb=None):
        t = threading.Thread(target=self._execute, args=(read_cb, close_cb))
        t.daemon = True
        t.start()

    def terminate(self):
        if not self.returncode and self._pipe:
            self._pipe.terminate()
