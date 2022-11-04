# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

__all__ = ['SafePopen']

import threading
import subprocess
import sys
import os
import struct
import errno

if sys.version_info.major > 2:
    from queue import Queue, Empty
else:
    from Queue import Queue, Empty

from io import open
from pupy.network.lib.pupyrpc import nowait

ON_POSIX = 'posix' in sys.builtin_module_names
DETACHED_PROCESS = 0x00000008


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
        self._detached = popen_kwargs.pop('detached', False)
        self._stdin_data = popen_kwargs.pop('stdin_data', None)
        self._suid = popen_kwargs.pop('suid', None)

        if self._detached:
            self._interactive = False

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
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

            self._popen_kwargs.update({
                'startupinfo': startupinfo,
                'creationflags': subprocess.CREATE_NEW_PROCESS_GROUP
            })

        if not self._detached and 'stderr' not in self._popen_kwargs:
            self._popen_kwargs['stderr'] = subprocess.STDOUT

    def _execute(self, read_cb, close_cb):
        returncode = None
        need_fork = False

        try:
            kwargs = self._popen_kwargs
            # Setup some required arguments
            kwargs.update({
                'bufsize': self._bufsize,
                'close_fds': ON_POSIX
            })

            if not self._detached:
                kwargs.update({
                    'stdin': subprocess.PIPE,
                    'stdout': subprocess.PIPE,
                })

            elif 'creationflags' in kwargs:
                kwargs['creationflags'] |= DETACHED_PROCESS
                for arg in ('stderr', 'stdin', 'stdout'):
                    if arg in kwargs:
                        del kwargs[arg]
            else:
                need_fork = True
                devnull = open(os.devnull, 'ab')
                kwargs.update({
                    'stdout': devnull,
                    'stderr': devnull,
                })

            if self._suid:
                kwargs.update({
                    'preexec_fn': lambda: prepare(self._suid)
                })

            if need_fork:
                p_read, p_write = os.pipe()
                pid = os.fork()
                if pid == 0:
                    os.close(p_read)

                    if 'preexec_fn' not in kwargs:
                        kwargs['preexec_fn'] = os.setsid

                    try:
                        self._pipe = subprocess.Popen(
                            *self._popen_args,
                            **kwargs
                        )

                        os.write(p_write, struct.pack('i', self._pipe.poll() or 0))

                    except OSError as e:
                        os.write(p_write, struct.pack('i', e.errno))

                    except Exception as e:
                        os.write(p_write, struct.pack('i', 1))

                    finally:
                        os.close(p_write)

                    os._exit(0)

                else:
                    os.close(p_write)
                    returncode, = struct.unpack('i', os.read(p_read, 4))
                    os.waitpid(pid, 0)

            else:
                self._pipe = subprocess.Popen(
                    *self._popen_args,
                    **kwargs
                )

            if self._pipe and self._pipe.stdin:
                if self._stdin_data:
                    self._pipe.stdin.write(self._stdin_data)
                    self._pipe.stdin.flush()

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

        if self._detached:
            if self._pipe:
                self.returncode = self._pipe.poll()
            else:
                self.returncode = returncode or None

            if close_cb:
                close_cb()
            return

        queue = Queue()
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
            read_cb = nowait(read_cb)

        if close_cb:
            close_cb = nowait(close_cb)

        t = threading.Thread(target=self._execute, args=(read_cb, close_cb))
        t.daemon = True
        t.start()

    def get_returncode(self):
        return errno.errorcode.get(
            self.returncode, self.returncode
        )

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
