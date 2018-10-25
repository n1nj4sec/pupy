# -*- coding: utf-8 -*-

import threading
import random
import string
import re
import os
import pupy
import builtins
import fcntl
import select

class USniper(pupy.Task):
    def __init__(self, manager, path, addr, reg='ax', ret=False, cast='', argtype=None):
        super(USniper, self).__init__(manager)

        self._path = path

        if not os.path.isabs(self._path) or not os.path.exists(self._path):
            raise ValueError('Executable {} not found'.format(self._path))

        if ret:
            self._match = re.compile(
                r'^\s*[^-]+-([\d]+)\s+\[[0-9]+\]\s+[a-z.]{4}\s(\d+)\.\d+:'
                r'\s+([^:]+):\s\(0x[a-f0-9]+\s\<\-\s0x[a-f0-9]+\)\s+arg1=(?:(?:0x)?([0-9a-f]+)|"([^"]+)"$)')
        else:
            self._match = re.compile(
                r'^\s*[^-]+-([\d]+)\s+\[[0-9]+\]\s+[a-z.]{4}\s(\d+)\.\d+:'
                r'\s+([^:]+):\s\(0x[a-f0-9]+\)\s+arg1=(?:(?:0x)?([0-9a-f]+)|"([^"]+)"$)')

        if type(addr) in (str, unicode):
            if addr.startswith('0x'):
                addr = int(addr[2:], 16)
            else:
                addr = int(addr)

        self._type = argtype
        self._ret = ret
        self._reg = '%' + reg
        self._cast = cast
        self._addr = hex(addr) if type(addr) in (int, long) else addr
        self._worker = None
        self._lock = threading.Lock()
        self._fs = '/sys/kernel/debug'
        self._pipe = None
        self._marker = ''.join(
            random.choice(string.ascii_uppercase + string.digits) for _ in range(16)
        )

        self._results = {}

        try:
            with open('{}/tracing/uprobe_events'.format(self._fs), 'w') as events:
                register = '{}:{} {}:{} {}\n'.format(
                    'r' if self._ret else 'p', self._marker, self._path, self._addr,
                    '+0({}):{}'.format(self._reg, self._cast) if self._cast else self._reg
                )
                events.write(register)

        except IOError:
            self._stopped.set()
            raise

        with open('{}/tracing/events/uprobes/{}/enable'.format(self._fs, self._marker), 'w') as trigger:
            trigger.write('1\n')


    @property
    def results(self):
        with self._lock:
            result = self._results
            self._results = {}
            return result

    def stop(self):
        self._stopped.set()
        with self._lock:
            if self._pipe:
                try:
                    os.close(self._pipe.fileno())
                except:
                    pass

        return True

    def task(self):
        try:
            with open('{}/tracing/trace_pipe'.format(self._fs), 'r') as trace:
                self._pipe = trace
                fd = trace.fileno()
                flag = fcntl.fcntl(fd, fcntl.F_GETFL)
                fcntl.fcntl(fd, fcntl.F_SETFL, flag | os.O_NONBLOCK)

                buf = ''

                while not self._stopped.is_set():
                    rlist = []

                    try:
                        rlist, _, xlist = select.select([trace], [], [trace], 10)
                    except:
                        break

                    if xlist:
                        break

                    if not rlist:
                        continue

                    try:
                        buf = buf + os.read(trace.fileno(), 4096)
                    except IOError:
                        break

                    if not buf:
                        break

                    if '\n' not in buf:
                        continue

                    if buf.endswith('\n'):
                        lines = buf.split('\n')
                        buf = ''
                    else:
                        last_n = buf.rfind('\n')
                        buf, lines = buf[last_n+1:], buf[:last_n].split('\n')

                    for line in lines:
                        if line.startswith('#'):
                            continue

                        groups = self._match.match(line)

                        if not groups or not groups.group(3) == self._marker:
                            continue

                        pid = groups.group(1)
                        ts = groups.group(2)
                        reg = groups.group(4)
                        string = groups.group(5)
                        if reg:
                            value = int(reg, 16)
                            if self._type:
                                value = self._type(value)
                        elif string:
                            value = string
                        else:
                            value = ''

                        with self._lock:
                            if pid not in self._results:
                                exe = os.readlink('/proc/{}/exe'.format(pid))
                                cmdline = []
                                with open('/proc/{}/cmdline'.format(pid)) as fcmdline:
                                    cmdline = [
                                        x for x in fcmdline.read().split('\x00') if x
                                    ]

                                self._results[pid] = {
                                    'exe': exe,
                                    'cmd': cmdline,
                                    'dump': {}
                                }

                            if ts not in self._results[pid]['dump']:
                                self._results[pid]['dump'][ts] = []

                            self._results[pid]['dump'][ts].append(value)

        except IOError, e:
            if not e.errno == 9:
                raise

        finally:
            with self._lock:
                if self._pipe:
                    self._pipe.close()
                    self._pipe = None

            with open('{}/tracing/events/uprobes/{}/enable'.format(self._fs, self._marker), 'w') as trigger:
                trigger.write('0\n')

            try:
                with open('{}/tracing/uprobe_events'.format(self._fs), 'w') as events:
                    events.write('-:{}\n'.format(self._marker))
            except:
                pass

def start(path, addr, reg='ax', ret=False, cast=None, argtype='chr', event_id=None):
    try:
        if pupy.manager.active(USniper):
            return False
    except:
        try:
            pupy.manager.stop(USniper)
        except:
            pass

    if argtype and hasattr(builtins, argtype):
        argtype = getattr(builtins, argtype)
    else:
        argtype = None

    return pupy.manager.create(
        USniper, path, addr, reg, ret, cast, argtype,
        event_id=event_id
    ) is not None

def stop():
    return pupy.manager.stop(USniper)

def dump():
    usniper = pupy.manager.get(USniper)
    if usniper:
        return usniper.results
