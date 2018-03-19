# -*- coding: utf-8 -*-

__all__ = [ 'SafePopen' ]

import threading
import subprocess
import Queue
import rpyc
import sys
import os
import shlex

ON_POSIX = 'posix' in sys.builtin_module_names

def read_pipe(queue, pipe, bufsize):
    completed = False
    returncode = None

    while not completed:
        try:
            returncode = pipe.poll()
            completed = returncode != None
        except Exception as e:
            continue

        try:
            if bufsize:
                data = pipe.stdout.read() \
                  if completed else pipe.stdout.readline(bufsize)
            else:
                data = pipe.stdout.read(1)
        except Exception:
            returncode = pipe.poll()
            break

        queue.put(data)

    queue.put(returncode)

class SafePopen(object):
    def __init__(self, *popen_args, **popen_kwargs):
        self._popen_args = popen_args
        self._interactive = popen_kwargs.get('interactive', False)

        self._popen_kwargs = {
            k:v for k,v in popen_kwargs.iteritems() \
            if not k in ( 'interactive' )
        }

        self._reader = None
        self._pipe = None
        self._bufsize = 8196

        if self._interactive:
            self._bufsize = 0

        self.returncode = None

        if hasattr(subprocess, 'STARTUPINFO'):
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= \
              subprocess.CREATE_NEW_CONSOLE | \
              subprocess.STARTF_USESHOWWINDOW

            self._popen_kwargs.update({
                'startupinfo': startupinfo,
            })

        if not 'stderr' in self._popen_kwargs:
            self._popen_kwargs['stderr'] = subprocess.STDOUT

    def _execute(self, read_cb, close_cb):
        returncode = None
        try:
            kwargs = self._popen_kwargs
            # Setup some required arguments
            kwargs.update({
                'stdout': subprocess.PIPE,
                'bufsize': self._bufsize,
                'close_fds': ON_POSIX
            })

            if self._interactive:
                kwargs.update({
                    'stdin': subprocess.PIPE
                })

            self._pipe = subprocess.Popen(
                *self._popen_args,
                **kwargs
            )

        except OSError as e:
            if read_cb:
                read_cb("[ LAUNCH ERROR: {} ]\n".format(e.strerror))
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
            data = []
            r = queue.get()
            while not type(r) == int:
                data.append(r)
                if queue.empty():
                    break
                else:
                    r = queue.get()

            if data and read_cb:
                read_cb(b''.join(data))

            if type(r) == int:
                self.returncode = r
                break

        if close_cb:
            close_cb()

    def execute(self, close_cb, read_cb=None):
        if read_cb:
            read_cb = rpyc.async(read_cb)

        if close_cb:
            close_cb = rpyc.async(close_cb)

        t = threading.Thread(target=self._execute, args=(read_cb, close_cb))
        t.daemon = True
        t.start()

    def get_returncode(self):
        return self.returncode

    def terminate(self):
        if not self.returncode and self._pipe:
            try:
                self._pipe.terminate()
            except:
                pass

    def write(self, data):
        if self.returncode or not self._pipe or not self._interactive:
            return

        self._pipe.stdin.write(data)
        self._pipe.stdin.flush()

def safe_exec(read_cb, close_cb, *args, **kwargs):
    sfp = SafePopen(*args, **kwargs)
    sfp.execute(close_cb, read_cb)

    return sfp.terminate, sfp.get_returncode

def check_output(cmdline, shell=True, env=None, encoding=None):
    p = subprocess.Popen(
        cmdline,
        shell=shell,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
        env=env
    )

    def get_data():
        stdout, stderr = p.communicate()
        if encoding:
            stdout = stdout.decode(encoding, errors='replace')

        retcode = p.poll()
        return stdout, retcode

    return p.terminate, get_data
