# -*- coding: utf-8 -*-

__all__ = ['SafePopen']

import threading
import subprocess
import Queue
import rpyc
import sys
import os

ON_POSIX = 'posix' in sys.builtin_module_names


def read_pipe(queue, pipe, bufsize):
    completed = False
    returncode = None

    while not completed:
        try:
            returncode = pipe.poll()
            completed = returncode is not None
        except Exception:
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


def prepare(suid):
    import pwd

    if suid is not None:
        try:
            if not type(suid) in (int, long):
                userinfo = pwd.getpwnam(suid)
                suid = userinfo.pw_uid
                sgid = userinfo.pw_gid
            else:
                userinfo = pwd.getpwuid(suid)
                sgid = userinfo.pw_gid
        except Exception:
            pass

        try:
            path = os.ttyname(sys.stdin.fileno())
            os.chown(path, suid, sgid)
        except Exception:
            pass

        try:
            os.initgroups(userinfo.pw_name, sgid)
            os.chdir(userinfo.pw_dir)
        except Exception:
            pass

        try:
            if hasattr(os, 'setresuid'):
                os.setresgid(suid, suid, sgid)
                os.setresuid(suid, suid, sgid)
            else:
                euid = os.geteuid()
                if euid != 0:
                    os.seteuid(0)
                    os.setegid(0)

                os.setgid(suid)
                os.setuid(suid)

        except Exception:
            pass

    os.setsid()


class SafePopen(object):
    def __init__(self, *popen_args, **popen_kwargs):
        self._popen_args = popen_args
        self._interactive = popen_kwargs.pop('interactive', False)
        self._suid = popen_kwargs.pop('suid', None)

        if not ON_POSIX:
            self._suid = None

        self._popen_kwargs = dict(popen_kwargs)

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

        if 'stderr' not in self._popen_kwargs:
            self._popen_kwargs['stderr'] = subprocess.STDOUT

    def _execute(self, read_cb, close_cb):
        returncode = None
        try:
            kwargs = self._popen_kwargs
            # Setup some required arguments
            kwargs.update({
                'stdin': subprocess.PIPE,
                'stdout': subprocess.PIPE,
                'bufsize': self._bufsize,
                'close_fds': ON_POSIX
            })

            if self._suid:
                kwargs.update({
                    'preexec_fn': lambda: prepare(self._suid)
                })

            self._pipe = subprocess.Popen(
                *self._popen_args,
                **kwargs
            )

            if not self._interactive:
                self._pipe.stdin.close()

        except OSError as e:
            if read_cb:
                read_cb("[ LAUNCH ERROR: {} ]\n".format(e.strerror))
            try:
                returncode = self._pipe.poll()
            except Exception:
                pass

            self.returncode = returncode if returncode is not None else -e.errno
            if close_cb:
                close_cb()
                return

        except Exception as e:
            if read_cb:
                read_cb("[ UNKNOWN ERROR: {} ]\n".format(e))

            try:
                returncode = self._pipe.poll()
            except Exception:
                pass

            self.returncode = returncode if returncode is not None else -1
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


def safe_exec(read_cb, close_cb, args, kwargs):
    kwargs = dict(kwargs)

    sfp = SafePopen(args, **kwargs)
    sfp.execute(close_cb, read_cb)

    return sfp.terminate, sfp.get_returncode


def check_output(cmdline, shell=True, env=None, encoding=None, suid=None):
    args = {
        'shell': shell,
        'stdin': subprocess.PIPE,
        'stdout': subprocess.PIPE,
        'stderr': subprocess.STDOUT,
        'universal_newlines': True,
        'env': env,
    }

    if ON_POSIX and suid:
        args['preexec_fn'] = lambda: prepare(suid)

    p = subprocess.Popen(
        cmdline,
        **args
    )

    complete = [False]

    def get_data():
        if complete[0]:
            return ''

        stdout, stderr = p.communicate()
        complete[0] = True

        if encoding:
            stdout = stdout.decode(encoding, errors='replace')

        retcode = p.poll()
        return stdout, retcode

    return p.terminate, get_data
