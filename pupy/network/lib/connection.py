# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

__all__ = (
    'SyncRequestDispatchQueue',
    'PupyConnection',
    'PupyConnectionThread'
)

import sys
import time
import weakref
import traceback

from threading import Thread, Lock, current_thread

if sys.version_info.major > 2:
    from queue import Queue, Full, Empty
else:
    from Queue import Queue, Full, Empty

from network.lib import getLogger

from network.lib.ack import Ack
from network.lib.buffer import Buffer

from network.lib.rpc.core import Connection, consts, brine, netref
from network.lib.rpc.core.consts import (
    HANDLE_PING, HANDLE_CLOSE, HANDLE_GETROOT,
    HANDLE_DIR, HANDLE_HASH, HANDLE_DEL
)

logger = getLogger('pconn')
synclogger = getLogger('sync')
syncqueuelogger = getLogger('syncqueue')


FAST_CALLS = (
    HANDLE_PING, HANDLE_CLOSE, HANDLE_GETROOT,

    HANDLE_DIR, HANDLE_HASH, HANDLE_DEL
)

PY2TO3_CALLATTRS = (
    '__getitem__', '__delitem__', '__setitem__',
    '__getattr__', '__delattr__', '__setattr__',
    '__getattribute__'
)

CONTROL_NOP = 0
CONTROL_ENABLE_BRINE_EXT_V1 = 1


# Monkeypatch brine to be buffer firendly


BRINE_VER_1 = 1
PING_V1_CONTROL_MAGIC = b'\x00CTRL\x00V1'


def stream_dump(obj, version=0):
    buf = Buffer()
    brine._dump(obj, buf, version)
    return buf


# Py2: bytes == str
@brine.register(brine._dump_registry, bytes)
def _dump_bytes_to_buffer(obj, stream, version):
    obj_len = len(obj)
    if obj_len == 0:
        stream.append(brine.TAG_EMPTY_STR)
        return
    elif obj_len < 5:
        if obj_len == 1:
            stream.append(brine.TAG_STR1)
        elif obj_len == 2:
            stream.append(brine.TAG_STR2)
        elif obj_len == 3:
            stream.append(brine.TAG_STR3)
        elif obj_len == 4:
            stream.append(brine.TAG_STR4)
    else:
        if obj_len < 256:
            stream.append(brine.TAG_STR_L1 + brine.I1.pack(obj_len))
        else:
            stream.append(brine.TAG_STR_L4 + brine.I4.pack(obj_len))

    stream.append(obj)


@brine.register(brine._dump_registry, Buffer)
def _dump_buffer_to_buffer(obj, stream, version):
    stream.append(brine.TAG_STR_L4 + brine.I4.pack(len(obj)))
    stream.append(obj)


brine.simple_types = list(brine.simple_types)
brine.simple_types.append(Buffer)
brine.dump = stream_dump

################################################################


class SyncRequestDispatchQueue(object):
    MAX_TASK_ACK_TIME = 0.5

    instance = None

    def __init__(self):
        self._queue = Queue(maxsize=256)
        self._workers = 1
        self._pending_workers = 0
        self._workers_lock = Lock()
        self._primary_worker = Thread(
            target=self._dispatch_request_worker,
            name="Primary SyncQueue Dispatcher"
        )
        self._primary_worker.daemon = True
        self._primary_worker.start()
        self._closed = False
        self._max_workers = 1
        self._promise = 0

    @staticmethod
    def get_queue():
        if not SyncRequestDispatchQueue.instance:
            SyncRequestDispatchQueue.instance = SyncRequestDispatchQueue()

        return SyncRequestDispatchQueue.instance

    def _dispatch_request_worker(self):

        name = current_thread().name

        if __debug__:
            syncqueuelogger.debug('New Worker(%s)', name)

        task = self._queue.get()
        while task and not self._closed:
            ack, on_error, func, args = task

            with self._workers_lock:
                ack.set()
                self._pending_workers += 1

            try:
                if __debug__:
                    syncqueuelogger.debug('Process task(%s) - start', name)

                func(*args)

                if __debug__:
                    syncqueuelogger.debug('Process task(%s) - complete', name)

            except Exception as e:
                if __debug__:
                    syncqueuelogger.debug(
                        'Process task(%s) - exception: func=%s args=%s '
                        'exc:%s/%s', name, func, args, type(e), e
                    )

                if on_error:
                    on_error(e)

            del func, args

            with self._workers_lock:
                self._queue.task_done()
                self._pending_workers -= 1

            again = False
            task = None

            try:
                task = self._queue.get_nowait()
                if __debug__:
                    syncqueuelogger.debug('Task acquired(%s) (no wait)', name)

            except Empty:
                with self._workers_lock:
                    if not self._closed and (
                        self._promise or self._workers <=
                            self._pending_workers + 1):
                        again = True
                    else:
                        self._workers -= 1

            if again:
                if __debug__:
                    syncqueuelogger.debug(
                        'Wait for task to be queued(%s)', name
                    )

                task = self._queue.get()

                if __debug__:
                    syncqueuelogger.debug('Task acquired(%s)', name)

        if __debug__:
            if not task:
                syncqueuelogger.debug(
                    'Worker(%s) closed by explicit request', name
                )

    def __call__(self, on_error, func, *args):
        with self._workers_lock:
            self._promise += 1

        ack = Ack()
        queued = False

        while not ack.is_set():
            if not queued:
                try:
                    if __debug__:
                        syncqueuelogger.debug('Queue task')

                    self._queue.put_nowait((ack, on_error, func, args))

                    if __debug__:
                        syncqueuelogger.debug('Task queued')

                    with self._workers_lock:
                        self._promise -= 1

                    queued = True

                except Full:
                    if __debug__:
                        syncqueuelogger.debug(
                            'Task not queued - no empty slots. '
                            'Launch new worker (%s, %s)',
                            self, self._pending_workers
                        )

                        pass

            if not queued or not ack.wait(
                    timeout=self.MAX_TASK_ACK_TIME, probe=0.1):
                with self._workers_lock:
                    if self._closed:
                        if __debug__:
                            syncqueuelogger.debug(
                                'Queue (%s) closed, do not start new worker',
                                self
                            )

                    self._workers += 1
                    if self._workers > self._max_workers:
                        self._max_workers = self._workers

                        if __debug__:
                            syncqueuelogger.info(
                                'Max workers(%s): %s',
                                self, self._max_workers)

                    thread = Thread(
                        target=self._dispatch_request_worker,
                        name="SyncQueue Dispatcher"
                    )
                    thread.daemon = True
                    thread.start()

    def close(self):
        with self._workers_lock:
            self._closed = True

            if __debug__:
                syncqueuelogger.debug('Queue(%s) closing: %s', self)

            try:
                while True:
                    try:
                        self._queue.put_nowait(None)
                    except Full:
                        break

            except Exception as e:
                if __debug__:
                    syncqueuelogger.exception(
                        'Queue(%s) close: error: %s', self, e
                    )

            if __debug__:
                syncqueuelogger.debug('Queue(%s) closed', self)


class PupyClientCababilities(object):
    __slots__ = ('_storage', '_version', '_acked')

    def __init__(self, version=0):
        self._storage = 0
        self._version = version
        self._acked = True

    def set(self, cap):
        self._storage |= cap

    def get(self, cap):
        return self._storage & cap == cap

    @property
    def version(self):
        return self._version

    @version.setter
    def version(self, version):
        if self._version != version:
            self._acked = False

        self._version = version

    def ack(self):
        result = self._acked
        self._acked = True
        return result


class PupyConnection(Connection):
    __slots__ = (
        '_initialized', '_deinitialized', '_closing',
        '_close_lock', '_sync_events_lock',
        '_async_events_lock', '_sync_events',
        '_sync_raw_replies', '_sync_raw_exceptions',
        '_last_recv', '_ping', '_ping_timeout',
        '_serve_timeout', '_last_ping', '_default_serve_timeout',
        '_queue', '_config', '_timer_event', '_timer_event_last',
        '_client_capabilities', '_3to2_mode'
    )

    def __repr__(self):
        return 'PC:{}'.format(self._config['connid'])

    def __init__(self, pupy_srv, *args, **kwargs):
        self._close_lock = Lock()
        self._sync_events_lock = Lock()
        self._async_events_lock = Lock()

        self._sync_events = {}
        self._sync_raw_replies = {}
        self._sync_raw_exceptions = {}

        self._last_recv = time.time()
        self._ping = True
        self._ping_timeout = 60
        self._serve_timeout = 600
        self._last_ping = None
        self._default_serve_timeout = 5
        self._queue = SyncRequestDispatchQueue.get_queue()

        self._timer_event = None
        self._timer_event_last = None
        self._initialized = False
        self._deinitialized = False
        self._closing = False

        self._client_capabilities = PupyClientCababilities()
        self._3to2_mode = False

        if 'ping' in kwargs:
            ping = kwargs.pop('ping')
        else:
            ping = None

        if 'timeout' in kwargs:
            timeout = kwargs.pop('timeout')
        else:
            timeout = None

        if 'timer_event' in kwargs:
            self._timer_event = kwargs.pop('timer_event')

        if ping or timeout:
            self.set_pings(ping, timeout)

        kwargs['_lazy'] = True
        Connection.__init__(self, *args, **kwargs)
        if pupy_srv:
            self._local_root.pupy_srv = pupy_srv

        if 'config' in kwargs:
            self._config.update(kwargs['config'])

        next(self._seqcounter)

        logger.debug('New PupyConnection: (%s)', self)

    def _on_sync_request_exception(self, exc):
        if __debug__:
            logger.exception(
                'Connection(%s) - sync request exception %s',
                self, exc
            )

        if not isinstance(exc, EOFError):
            logger.exception('%s: %s', self, exc)

        self.close()

    # def _netref_factory(self, oid, clsname, modname):
    #     return super(PupyConnection, self)._netref_factory(
    #         oid, clsname, modname
    #     )

    def consume(self):
        return self._channel.consume()

    def wake(self):
        self._channel.wake()

    def activate_3to2(self):
        self._3to2_mode = True

    def is_3to2(self):
        return self._3to2_mode

    def set_pings(self, ping=None, timeout=None):
        if ping is not None:
            try:
                self._serve_timeout = int(ping)
            except ValueError:
                self._serve_timeout = 10

                self._ping = ping and ping not in (
                    '0', '-1', 'N', 'n', 'false', 'False', 'no', 'No'
                )

            self._ping = bool(ping)

        if timeout:
            try:
                self._ping_timeout = int(timeout)
            except ValueError:
                self._ping_timeout = 2

        return self.get_pings()

    def _handle_ping(self, data):
        if data.startswith(PING_V1_CONTROL_MAGIC):
            payload = brine.load(data[len(PING_V1_CONTROL_MAGIC):])
            self._dispatch_pupy_control(*payload)
            return b''

        return data

    def get_pings(self):
        if self._ping:
            return self._serve_timeout, self._ping_timeout
        else:
            return None, None

    def sync_request(self, handler, *args):
        try:
            seq = self._send_request(handler, args)
        except EOFError:
            self.close()
            raise

        if __debug__:
            trace = traceback.extract_stack()
            if len(trace) >= 4:
                synclogger.debug(
                    'Sync request wait(%s): %s / %s:%s %s (%s)',
                    self, seq, *trace[-4]
                )

        self._sync_events[seq].wait()

        if __debug__:
            synclogger.debug(
                'Sync request wait(%s): %s - complete', self, seq)

        del self._sync_events[seq]

        if __debug__:
            synclogger.debug('Sync request process(%s): %s', self, seq)

        is_response = False
        is_exception = False

        with self._sync_events_lock:
            is_response = seq in self._sync_raw_replies
            is_exception = seq in self._sync_raw_exceptions

        if is_response:
            if __debug__:
                synclogger.debug(
                    'Dispatch sync reply(%s): %s - start', self, seq)

            Connection._dispatch_reply(
                self, seq, self._sync_raw_replies.pop(seq),
                self._client_capabilities.version
            )

            if __debug__:
                synclogger.debug(
                    'Dispatch sync reply(%s): %s - complete', self, seq)

        if is_exception:
            if __debug__:
                synclogger.debug(
                    'Dispatch sync exception(%s): %s - start', self, seq
                )
                synclogger.debug(
                    'Dispatch sync exception(%s): %s - handler = %s(%s) '
                    'args = %s',
                    self, seq,
                    self._HANDLERS[handler], handler,
                    repr(args)
                )

            Connection._dispatch_exception(
                self, seq, self._sync_raw_exceptions.pop(seq),
                self._client_capabilities.version
            )

            if __debug__:
                synclogger.debug(
                    'Dispatch sync exception(%s): %s - complete', self, seq)

        if __debug__:
            synclogger.debug(
                'Sync request(%s): %s - complete', self, seq)

        if self.closed:
            raise EOFError(
                'Connection was closed, seq({}): {}'.format(self, seq))

        isexc, obj = self._sync_replies.pop(seq)
        if isexc:
            raise obj
        else:
            return obj

    def _send_control(self, code, data=None, timeout=None):
        # Use PING command to send controls
        # For compatibility

        payload = brine.dump((code, data))
        payload.insert(PING_V1_CONTROL_MAGIC)

        return self.async_request(
            consts.HANDLE_PING, payload, timeout=timeout
        )

    def _py2to3_conv(self, handler, args):
        if handler in (consts.HANDLE_GETATTR, consts.HANDLE_DELATTR):
            oid, name = args
            return (oid, name.encode('utf-8'))
        elif handler == consts.HANDLE_SETATTR:
            oid, name, value = args
            return (oid, name.encode('utf-8'), value)
        elif handler == consts.HANDLE_CALLATTR:
            oid, name, args, kwargs = args

            if name in PY2TO3_CALLATTRS:
                first, rest = args[0], args[1:]
                first = first.encode('utf-8')
                args = [first]
                args.extend(rest)
                args = tuple(args)

            if kwargs is not None:
                kwargs = tuple(
                    (key.encode('utf-8'), value)
                    for (key, value) in kwargs
                )

            return (oid, name.encode('utf-8'), args, kwargs)
        elif handler == consts.HANDLE_CALL:
            oid, args, kwargs = args

            if kwargs is not None:
                kwargs = tuple(
                    (key.encode('utf-8'), value)
                    for (key, value) in kwargs
                )

            return (oid, args, kwargs)

        return args

    def _netref_factory(self, oid, clsname, modname):
        typeinfo = (clsname, modname)
        if typeinfo in self._netref_classes_cache:
            # print("Use cached netref", typeinfo)
            cls = self._netref_classes_cache[typeinfo]
        elif not self._3to2_mode and typeinfo in netref.builtin_classes_cache:
            # print("Use builtin netref", typeinfo)
            cls = netref.builtin_classes_cache[typeinfo]
        else:
            info = self.sync_request(consts.HANDLE_INSPECT, oid)
            cls = netref.class_factory(
                clsname, modname, info
            )
            self._netref_classes_cache[typeinfo] = cls
            # print("Use inspect netref", typeinfo, "as", cls, "info", info)
        return cls(weakref.ref(self), oid)

    def _send_request(self, handler, args, nowait=None):
        if self._3to2_mode:
            args = self._py2to3_conv(handler, args)
            # print("SEND REQUEST", handler, args)

        seq = next(self._seqcounter)
        if nowait:
            if __debug__:
                logger.debug('Async request(%s): %s', self, seq)

            self._async_callbacks[seq] = nowait
        else:
            if __debug__:
                synclogger.debug('Sync request(%s): %s', self, seq)

            self._sync_events[seq] = Ack()

        self._send(
            consts.MSG_REQUEST, seq, (
                handler, self._box(
                    args, self._client_capabilities.version
                )
            ),
            self._client_capabilities.version
        )

        if __debug__:
            synclogger.debug('Request submitted(%s): %s', self, seq)

        return seq

    def _async_request(self, handler, args=(), callback=(lambda a, b: None)):
        self._send_request(handler, args, nowait=callback)

    def _dispatch_reply(self, seq, raw):
        if __debug__:
            logger.debug('Dispatch reply(%s): %s - start', self, seq)

        self._last_recv = time.time()

        is_sync = False
        with self._async_events_lock:
            is_sync = seq not in self._async_callbacks

        if is_sync:
            self._sync_raw_replies[seq] = raw
            if __debug__:
                logger.debug(
                    'Dispatch sync reply(%s): %s - pass', self, seq)
            self._sync_events[seq].set()

        else:
            # We hope here that this request will not block x_x
            if __debug__:
                logger.debug(
                    'Dispatch async reply(%s): %s - start', self, seq)

            Connection._dispatch_reply(
                self, seq, raw,
                self._client_capabilities.version
            )

            if __debug__:
                logger.debug(
                    'Dispatch async reply(%s): %s - complete', self, seq)

    def _dispatch_exception(self, seq, raw):
        if __debug__:
            logger.debug('Dispatch exception(%s): %s', self, seq)

        self._last_recv = time.time()

        is_sync = False
        with self._async_events_lock:
            is_sync = seq not in self._async_callbacks

        if is_sync:
            self._sync_raw_exceptions[seq] = raw
            if __debug__:
                logger.debug(
                    'Dispatch sync exception(%s): %s - pass',
                    self, seq
                )
            self._sync_events[seq].set()
        else:
            if __debug__:
                logger.debug(
                    'Dispatch async reply(%s): %s - start', self, seq)

            Connection._dispatch_exception(
                self, seq, raw,
                self._client_capabilities.version
            )

            if __debug__:
                logger.debug(
                    'Dispatch async reply(%s): %s - complete', self, seq)

    def _close_rpyc(self, _catchall=True):
        if self._closed:
            return

        self._closed = True

        if __debug__:
            trace = traceback.extract_stack()
            if len(trace) >= 2:
                logger.debug(
                    'Connection(%s) - close - start (at: %s:%s %s(%s))',
                    self, *trace[-2]
                )

        try:
            self._async_request(consts.HANDLE_CLOSE)
        except EOFError as e:
            logger.info(
                'Connection(%s) - close - notification failed '
                'because of EOF (%s)', self, e)

        except Exception:
            if not _catchall:
                raise

    def _close_chan(self, _catchall=True):
        if self._deinitialized:
            if __debug__:
                logger.debug('Connection(%s) - already deinitialized', self)

            return

        self._deinitialized = True

        try:
            if __debug__:
                logger.debug('Connection(%s) - cleanup', self)

            self._cleanup(_anyway=True)

            if self._channel and hasattr(self._channel, 'wake'):
                if __debug__:
                    logger.debug(
                        'Connection(%s) - wake buf_in (%s)',
                        self, self._channel
                    )

                self._channel.wake()

        except Exception as e:
            if __debug__:
                logger.debug(
                    'Connection(%s) - cleanup exception - %s', self, e
                )
            pass

        if __debug__:
            logger.debug('Connection(%s) - cleanup locks', self)

        with self._sync_events_lock:
            for lock in self._sync_events.values():
                try:
                    lock.set()
                except Exception as e:

                    if __debug__:
                        logger.exception(
                            'Connection(%s) - ack failed: %s', self, e)

                    pass

        if __debug__:
            try:
                logger.debug('Connection(%s) - closed:', self)
            except Exception as e:
                logger.exception(e)

    def close(self, _catchall=True):
        with self._close_lock:
            if self._closing:
                return

            self._closing = True

        try:
            self._close_rpyc(_catchall)
        except Exception as e:
            if __debug__:
                logger.exception('Connection(%s) - rpyc close - %s', self, e)

            pass

        try:
            self._close_chan(_catchall)
        except Exception as e:
            if __debug__:
                logger.exception('Connection(%s) - chan close - %s', self, e)

            pass

    @property
    def inactive(self):
        return time.time() - self._last_recv

    def serve(self, timeout=None):
        raise NotImplementedError('Serve method should not be used!')

    def _init_service_with_notify(self, timeout):
        def check_timeout(promise):
            now = time.time()

            logger.debug('Check timeout(%s) - start', self)

            while (time.time() - now < timeout) and not self.closed:
                if promise.expired:
                    logger.info('Check timeout(%s) - failed', self)
                    self.close()
                    break
                elif promise.ready:
                    logger.debug('Check timeout(%s) - ok', self)
                    self._initialized = True
                    break
                else:
                    time.sleep(1)

        if self._local_root:
            promise = self._send_control(
                CONTROL_ENABLE_BRINE_EXT_V1, timeout=timeout
            )

            t = Thread(
                target=check_timeout, args=(promise,),
                name="PupyConnection({}) Timeout check".format(self)
            )
            t.daemon = True
            t.start()

            try:
                self._init_service()
            except AttributeError as e:
                if __debug__:
                    logger.exception('Init service failed: %s', e)
                # Connection was broken in the middle
                raise EOFError('Connection was broken in the middle')
        else:
            logger.debug('Local root is absent')

    def init(self, timeout=60):
        self._queue(
            self._on_sync_request_exception,
            self._init_service_with_notify,
            timeout
        )

    def loop(self):
        if __debug__:
            logger.debug('Serve loop(%s) started', self)

        if not self._timer_event_last:
            self._timer_event_last = time.time()

        while not self.closed:
            if self._timer_event:
                period, callback = self._timer_event

                if self._timer_event_last + period < time.time():
                    try:
                        callback()
                    except Exception as e:
                        logger.exception(
                            'Callback exception(%s): %s: %s',
                            self, type(e), e)

            try:
                timeout = None
                if not self._initialized:
                    timeout = 1

                data = self._serve(timeout)

                self._dispatch(data)
                continue

            except EOFError as e:
                logger.info('Serve loop(%s) - EOF (%s)', self, e)

            except Exception as e:
                logger.exception(
                    'Exception(%s): %s: %s', self, type(e), e)

            break

        if __debug__:
            logger.debug('Serve loop(%s) completed', self)

        self.close()

    def _serve(self, timeout=None):
        ''' Check timeouts every serve cycle '''

        interval, ping_timeout = self.get_pings()

        if timeout is None:
            timeout = interval or self._default_serve_timeout

        now = time.time()
        mintimeout = timeout

        data = None

        for async_event_id in self._async_callbacks.keys():
            async_event = self._async_callbacks.get(async_event_id, None)
            if not async_event:
                continue

            if not hasattr(async_event, '_ttl') or not async_event._ttl:
                continue

            if async_event._ttl < now:
                raise EOFError('Async timeout! ({})'.format(self))

            etimeout = async_event._ttl - now

            if __debug__:
                logger.debug(
                    'Check timeouts: (%s) etimeout = %s / mintimeout = %s /'
                    ' ttl = %s',
                    self, etimeout, mintimeout, async_event._ttl
                )

            if mintimeout is None or etimeout < mintimeout:
                mintimeout = etimeout

        timeout = mintimeout

        if __debug__:
            logger.debug(
                'Serve(%s): start / timeout = %s / interval = %s '
                '/ ping timeout = %s / %s',
                self, timeout, interval, ping_timeout, self._last_ping
            )

        data = self._recv(timeout, wait_for_lock=False)

        if __debug__:
            logger.debug(
                'Serve(%s): complete / data = %s',
                self, len(data) if data else None
            )

        if not data and interval and ping_timeout:
            if not self._last_ping or now > self._last_ping + interval:
                if __debug__:
                    logger.debug(
                        'Send ping, interval(%s): %d, timeout: %d',
                        self, interval, ping_timeout
                    )

                self._last_ping = self.ping(timeout=ping_timeout, now=now)
            else:
                if __debug__:
                    logger.debug(
                        'Ping not required(%s): %d < %d',
                        self, self._last_ping or now,
                        self._last_ping + interval
                    )

        return data

    def is_extended(self):
        return self._client_capabilities.version > 0

    def _dispatch_pupy_control(self, code, *args):
        if __debug__:
            logger.debug(
                'Processing pupy brine control: args: %s', args
            )

        if code == CONTROL_ENABLE_BRINE_EXT_V1:
            self._client_capabilities.version = 1

            if not self._client_capabilities.ack():
                self._send_control(CONTROL_ENABLE_BRINE_EXT_V1)

            if __debug__:
                logger.debug('Client supports brine extensions V1')

    def _dispatch(self, data):
        if __debug__:
            logger.debug('Dispatch(%s) start', self)

        now = time.time()

        if data:
            if __debug__:
                logger.debug('Dispatch(%s) - data (%s)', self, len(data))

            msg, seq, args = brine._load(
                data, self._client_capabilities.version
            )

            if msg == consts.MSG_REQUEST:
                if __debug__:
                    logger.debug(
                        'Processing message request, type(%s): '
                        '%s seq: %s - started',
                        self, args[0], seq
                    )

                handler = args[0]

                if handler in FAST_CALLS:
                    self._dispatch_request(
                        seq, args, self._client_capabilities.version
                    )
                else:
                    self._queue(
                        self._on_sync_request_exception,
                        self._dispatch_request,
                        seq, args, self._client_capabilities.version
                    )

            else:
                if __debug__:
                    logger.debug(
                        'Processing message response, seq(%s): '
                        '%s - started', self, seq
                    )

                if msg == consts.MSG_REPLY:
                    self._dispatch_reply(seq, args)
                elif msg == consts.MSG_EXCEPTION:
                    self._dispatch_exception(seq, args)
                else:
                    raise ValueError("invalid message type: %r" % (msg,))

                if __debug__:
                    logger.debug(
                        'Processing message, seq(%s): '
                        '%s - completed', self, seq
                    )

            self._last_ping = now

        elif self.closed:
            if __debug__:
                logger.debug('Dispatch interrupt(%s) - closed', self)

            return
        else:
            if __debug__:
                logger.debug('Dispatch(%s) - no data', self)

        for async_event_id in self._async_callbacks.keys():
            async_event = self._async_callbacks.get(async_event_id)
            if not async_event:
                continue

            if not hasattr(async_event, '_ttl'):
                continue

            if async_event._ttl and async_event._ttl < now:
                raise EOFError(
                    'Async timeout! ({}, event={})'.format(self, async_event),
                    async_event)

    def defer(self, command, *args):
        if not self.closed:
            self._queue(command, *args)

    def ping(self, timeout=30, now=None, block=False):
        ''' RPyC do not have any PING handler. So.. why to wait? '''
        now = now or time.time()
        promise = self.async_request(
            consts.HANDLE_PING, b'ping', timeout=timeout
        )
        if block:
            promise.wait()

        return now

    Connection._HANDLERS[consts.HANDLE_PING] = _handle_ping


class PupyConnectionThread(Thread):
    def __init__(self, *args, **kwargs):
        if __debug__:
            logger.debug('Create connection thread')

        self.pupy_srv = args[0]
        self.connection = PupyConnection(*args, **kwargs)

        Thread.__init__(self)
        self.daemon = True
        self.name = 'PupyConnection({}) Thread'.format(self.connection)

        if __debug__:
            logger.debug(
                'Create connection(%s) thread completed',
                self.connection
            )

    def run(self):
        if __debug__:
            logger.debug('Run connection thread')

        self.connection.init()
        self.connection.loop()

        if __debug__:
            logger.debug('Connection thread closed')
