# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

__all__ = ['acquire', 'release']

import sys
import os
import os.path
import termios
import pty
import fcntl
import subprocess
import select
import rpyc
import array
import pwd
import errno
import shlex

from collections import deque

from pupy import manager, Task

DEFAULT_SHELL = None

def propose_shell():
    PATHS = os.environ.get(
        'PATH', '/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:/system/bin'
    ).split(':')

    SHELLS = ['bash', 'ash', 'zsh', 'sh', 'ksh', 'csh']

    for shell in (os.path.join(p, shell) for shell in SHELLS for p in PATHS):
        yield shell

    if 'SHELL' in os.environ:
        yield os.environ['SHELL']

    if os.path.isfile('/etc/shells'):
        with open('/etc/shells', 'r') as shells:
            for shell in shells:
                shell = shell.strip()
                if not shell.startswith('/'):
                    continue

                yield shell

def find_shell():
    global DEFAULT_SHELL

    if not DEFAULT_SHELL:
        for shell in propose_shell():
            if os.path.isfile(shell) and os.access(shell, os.X_OK):
                DEFAULT_SHELL = shell
                break

    if not DEFAULT_SHELL:
        DEFAULT_SHELL = '/bin/sh'

    return DEFAULT_SHELL

def prepare(suid):
    if suid is not None:
        try:
            if not type(suid) in (int, long):
                userinfo = pwd.getpwnam(suid)
                suid = userinfo.pw_uid
                sgid = userinfo.pw_gid
            else:
                userinfo = pwd.getpwuid(suid)
                sgid = userinfo.pw_gid
        except:
            pass

        try:
            path = os.ttyname(sys.stdin.fileno())
            os.chown(path, suid, sgid)
        except:
            pass

        try:
            os.initgroups(userinfo.pw_name, sgid)
            os.chdir(userinfo.pw_dir)
        except:
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
        except:
            pass

    os.setsid()
    try:
        fcntl.ioctl(sys.stdin, termios.TIOCSCTTY, 0)
    except:
        # No life without control terminal :(
        os._exit(-1)

class PtyShell(Task):
    __slots__ = (
        'prog', 'master', 'real_stdout',
        'argv', 'term', 'suid',
        'read_cb', 'close_cb', '_buffer'
    )

    def __init__(self, manager, argv=None, term=None, suid=None):
        super(PtyShell, self).__init__(manager)

        self.prog = None
        self.master = None
        self.real_stdout = sys.stdout

        self.argv = argv
        self.term = term
        self.suid = suid

        self.read_cb = None
        self.close_cb = None

        self._buffer = deque(maxlen=50)

    def stop(self):
        super(PtyShell, self).stop()
        self.close()

    def close(self):
        if self.prog is not None:
            rc = None

            try:
                rc = self.prog.poll()
            except:
                pass

            if rc is None:
                try:
                    self.prog.terminate()
                except:
                    pass

                try:
                    if self.prog.poll() is None:
                        self.prog.kill()
                except:
                    pass

                try:
                    self.prog.communicate()
                except:
                    pass

        if self.master:
            try:
                self.master.close()
            except:
                pass

            self.master = None

        if self._buffer:
            self._buffer.clear()
            self._buffer = None

        self.read_cb = None
        self.write_cb = None

        self.argv = None
        self.term = None
        self.suid = None

        self.prog = None
        self.master = None
        self.real_stdout = None

    def task(self):
        argv = None

        if not self.argv:
            argv = [find_shell()]

        elif type(self.argv) in (str, unicode):
            argv = shlex.split(self.argv)
        else:
            argv = self.argv

        PS1 = '[pupy]> '

        if argv:
            shell = os.path.basename(argv[0])
            if shell == 'bash':
                PS1 = r'[pupy:\W]> '
                argv.insert(1, '--norc')
                argv.insert(1, '--noprofile')
        else:
            argv = ['/bin/sh']

        if self.term is not None:
            os.environ['TERM'] = self.term

        ## Workaround via openpty grantpt behaviour
        euid = os.geteuid()
        uid = os.getuid()

        if euid != uid:
            os.seteuid(uid)

        master, slave = pty.openpty()

        if euid != uid:
            os.seteuid(euid)

        self.master = os.fdopen(master, 'rb+wb', 0) # open file in an unbuffered mode
        flags = fcntl.fcntl(self.master, fcntl.F_GETFL)
        assert flags >= 0
        flags = fcntl.fcntl(self.master, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        assert flags >= 0

        env = os.environ.copy()
        env.update({
            'PS1': PS1,
            'HISTFILE': '/dev/null',
            'PATH': ':'.join([
                '/bin', '/sbin', '/usr/bin', '/usr/sbin',
                '/usr/local/bin', '/usr/local/sbin'
            ])
        })

        if 'PATH' in os.environ:
            env['PATH'] += ':' + os.environ['PATH']

        suid = self.suid
        if suid is None and euid != uid:
            suid = euid

        if suid is not None:
            try:
                suid = int(suid)
            except:
                pass

            try:
                if type(suid) == int:
                    info = pwd.getpwuid(suid)
                else:
                    info = pwd.getpwnam(suid)

                env['USER'] = info.pw_name
                env['HOME'] = info.pw_dir
                env['LOGNAME'] = info.pw_name
            except:
                pass

        self.prog = subprocess.Popen(
            shell=False,
            args=argv,
            stdin=slave,
            stdout=slave,
            stderr=subprocess.STDOUT,
            preexec_fn=lambda: prepare(suid),
            env=env
        )
        os.close(slave)

        try:
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

    def write(self, data):
        if not self.master:
            return

        try:
            self.master.write(data)
            self.master.flush()

        except:
            self.stop()

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

    def set_pty_size(self, p1, p2, p3, p4):
        if not self.master:
            return

        buf = array.array('h', [p1, p2, p3, p4])
        try:
            fcntl.ioctl(self.master, termios.TIOCSWINSZ, buf)
        except:
            pass

    def _read_loop(self):
        not_eof = True
        fd = self.master.fileno()

        while not_eof and self.master:
            r, x = None, None

            try:
                r, _, x = select.select([self.master], [], [self.master], None)
            except OSError, e:
                if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                    continue
            except Exception, e:
                break

            if x or r:
                try:
                    data = os.read(fd, 32768)
                except OSError, e:
                    if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                        continue
                except Exception:
                    data = None

                if data:
                    self._buffer.append(data)

                    if self.read_cb:
                        self.read_cb(data)
                else:
                    not_eof = False

            if not_eof:
                not_eof = self.prog.poll() is None
            else:
                break

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
