# -*- coding: utf-8 -*-

import time

from rpyc.core import Connection, consts, brine
from threading import Thread, Event, Lock, RLock
from Queue import Queue, Full, Empty

import logging

logger = None
logger = logging.getLogger('pconn')
synclogger = logging.getLogger('sync')
syncqueuelogger = logging.getLogger('syncqueue')

from network.lib.buffer import Buffer

############# Monkeypatch brine to be buffer firendly #############
def stream_dump(obj):
    buf = Buffer()
    brine._dump(obj, buf)
    return buf

@brine.register(brine._dump_registry, str)
def _dump_str_to_buffer(obj, stream):
    l = len(obj)
    if l == 0:
        stream.append(brine.TAG_EMPTY_STR)
        return
    elif l < 5:
        if l == 1:
            stream.append(brine.TAG_STR1)
        elif l == 2:
            stream.append(brine.TAG_STR2)
        elif l == 3:
            stream.append(brine.TAG_STR3)
        elif l == 4:
            stream.append(brine.TAG_STR4)
    else:
        if l < 256:
            stream.append(brine.TAG_STR_L1 + brine.I1.pack(l))
        else:
            stream.append(brine.TAG_STR_L4 + brine.I4.pack(l))

    stream.append(obj)

@brine.register(brine._dump_registry, Buffer)
def _dump_buffer_to_buffer(obj, stream):
    stream.append(brine.TAG_STR_L4 + brine.I4.pack(len(obj)))
    stream.append(obj)

brine.simple_types = list(brine.simple_types)
brine.simple_types.append(Buffer)
brine.dump = stream_dump

################################################################

# Event (cond var) is simply to complex for our dumb case
# for c in ( Event, Ack ):
#     start = time.time()
#     for x in xrange(1000000):
#         a = c()
#         a.is_set()
#         a.set()
#         a.wait()
#     print c, time.time() - start
#
# <function Event at 0x7fc42a3681b8> 14.4261770248
# <class '__main__.Ack'> 3.26524806023

class Ack(object):
    """ Dumb (and fast, and unsafe) event replacement """

    __slots__ = ( '_lock', '_is_set', '_wait_lock' )

    def __init__(self):
        self._lock = Lock()
        self._is_set = False
        self._wait_lock = None

    def is_set(self):
        with self._lock:
            return self._is_set

    def set(self):
        with self._lock:
            self._is_set = True
            if self._wait_lock:
                self._wait_lock.release()
                self._wait_lock = None

    def wait(self, timeout=None, probe=0.5):
        if not timeout:
            with self._lock:
                if self._is_set:
                    return True

                self._wait_lock = Lock()
                self._wait_lock.acquire()

            self._wait_lock.acquire()
        else:
            with self._lock:
                if self._is_set:
                    return True

            delay = 0.0005
            prev = time.time()
            while timeout > 0:
                time.sleep(delay)
                now = time.time()
                timeout -= now - prev
                prev = now
                delay = min(timeout, probe, delay*2)

                with self._lock:
                    if self._is_set:
                        return True

            return False

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
        if __debug__:
            syncqueuelogger.debug('New Worker')

        task = self._queue.get()
        while task and not self._closed:
            ack, on_error, func, args = task

            with self._workers_lock:
                ack.set()
                self._pending_workers += 1

            try:
                if __debug__:
                    syncqueuelogger.debug('Process task - start')

                func(*args)

                if __debug__:
                    syncqueuelogger.debug('Process task - complete')

            except Exception, e:
                if __debug__:
                    syncqueuelogger.debug('Process task - exception: {}'.format(e))

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
                    syncqueuelogger.debug('Task acquired (no wait)')

            except Empty:
                with self._workers_lock:
                    if not self._closed and ( self._promise or self._workers <= self._pending_workers + 1 ):
                        again = True
                    else:
                        self._workers -= 1

            if again:
                if __debug__:
                    syncqueuelogger.debug('Wait for task to be queued')

                task = self._queue.get()

                if __debug__:
                    syncqueuelogger.debug('Task acquired')

        if __debug__:
            if not task:
                syncqueuelogger.debug('Worker closed by explicit request')

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
                            'Task not queued - no empty slots. Launch new worker'.format(
                                self._pending_workers))

                        pass

            if not queued or not ack.wait(timeout=self.MAX_TASK_ACK_TIME, probe=0.1):
                with self._workers_lock:
                    self._workers += 1
                    if self._workers > self._max_workers:
                        self._max_workers = self._workers

                        if __debug__:
                            syncqueuelogger.info(
                                'Max workers: {}'.format(self._max_workers))

                thread = Thread(
                    target=self._dispatch_request_worker,
                    name="SyncQueue Dispatcher"
                )
                thread.daemon = True
                thread.start()

    def close(self):
        self._closed = True
        while True:
            try:
                self._queue.put_nowait(None)
            except Full:
                break

class PupyConnection(Connection):
    def __init__(self, pupy_srv, *args, **kwargs):
        self._close_lock = Lock()

        self._sync_events = {}
        self._sync_raw_replies = {}
        self._sync_raw_exceptions = {}

        self._last_recv = time.time()
        self._ping = False
        self._ping_timeout = 30
        self._serve_timeout = 10
        self._last_ping = None
        self._default_serve_timeout = 5
        self._queue = SyncRequestDispatchQueue.get_queue()
        self._data_queue = Queue()
        self._serve_thread = Thread(
            target=self._serve_loop,
            name="PupyConnection Serve Loop"
        )
        self._serve_thread.daemon = True

        self._serve_interrupt = Event()

        if 'ping' in kwargs:
            ping = kwargs['ping']
            del kwargs['ping']
        else:
            ping = None

        if 'timeout' in kwargs:
            timeout = kwargs['timeout']
            del kwargs['timeout']
        else:
            timeout = None

        if ping or timeout:
            self.set_pings(ping, timeout)

        kwargs['_lazy'] = True
        Connection.__init__(self, *args, **kwargs)
        if pupy_srv:
            self._local_root.pupy_srv = pupy_srv

        if 'config' in kwargs:
            self._config.update(kwargs['config'])

        next(self._seqcounter)

        self._serve_thread.start()

    def _queue_dispatch_request(self, seq, args):
        self._queue(
            self._on_sync_request_exception,
            self._dispatch_request, seq, args)

    def _on_sync_request_exception(self, exc):
        if not isinstance(exc, EOFError):
            logger.exception(exc)

        self.close()

    def consume(self):
        return self._channel.consume()

    def wake(self):
        self._channel.wake()

    def set_pings(self, ping=None, timeout=None):
        if ping is not None:
            try:
                self._serve_timeout = int(ping)
            except:
                self._serve_timeout = 10

                self._ping = ping and ping not in (
                    '0', '-1', 'N', 'n', 'false', 'False', 'no', 'No'
                )

            self._ping = bool(ping)

        if timeout:
            try:
                self._ping_timeout = int(timeout)
            except:
                self._ping_timeout = 2

        return self.get_pings()

    def get_pings(self):
        if self._ping:
            return self._serve_timeout, self._ping_timeout
        else:
            return None, None

    def sync_request(self, handler, *args):
        seq = self._send_request(handler, args)
        if __debug__:
            synclogger.debug('Sync request wait: {}'.format(seq))

        self._sync_events[seq].wait()

        if __debug__:
            synclogger.debug('Sync request wait: {} - complete'.format(seq))

        del self._sync_events[seq]

        if __debug__:
            synclogger.debug('Sync request process: {}'.format(seq))

        _sync_raw_replies = self._sync_raw_replies.keys()
        if seq in _sync_raw_replies:
            if __debug__:
                synclogger.debug('Dispatch sync reply: {} - start'.format(seq))

            Connection._dispatch_reply(
                self, seq, self._sync_raw_replies.pop(seq))

            if __debug__:
                synclogger.debug('Dispatch sync reply: {} - complete'.format(seq))

        del _sync_raw_replies

        _sync_raw_exceptions = self._sync_raw_exceptions.keys()
        if seq in _sync_raw_exceptions:
            if __debug__:
                synclogger.debug('Dispatch sync exception: {} - start'.format(seq))

            Connection._dispatch_exception(
                self, seq, self._sync_raw_exceptions.pop(seq))

            if __debug__:
                synclogger.debug('Dispatch sync exception: {} - complete'.format(seq))

        del _sync_raw_exceptions

        if __debug__:
            synclogger.debug('Sync request: {} - complete'.format(seq))

        if self.closed:
            raise EOFError('Connection was closed, seq: {}'.format(seq))

        isexc, obj = self._sync_replies.pop(seq)
        if isexc:
            raise obj
        else:
            return obj

    def _send_request(self, handler, args, async=None):
        seq = next(self._seqcounter)
        if async:
            if __debug__:
                logger.debug('Async request: {}'.format(seq))

            self._async_callbacks[seq] = async
        else:
            if __debug__:
                synclogger.debug('Sync request: {}'.format(seq))

            self._sync_events[seq] = Ack()

        self._send(consts.MSG_REQUEST, seq, (handler, self._box(args)))

        if __debug__:
            synclogger.debug('Request submitted: {}'.format(seq))

        return seq

    def _async_request(self, handler, args = (), callback = (lambda a, b: None)):
        self._send_request(handler, args, async=callback)

    def _dispatch_reply(self, seq, raw):
        if __debug__:
            logger.debug('Dispatch reply: {} - start'.format(seq))

        self._last_recv = time.time()

        _async_callbacks = self._async_callbacks.keys()
        sync = seq not in _async_callbacks
        del _async_callbacks

        if sync:
            self._sync_raw_replies[seq] = raw
            if __debug__:
                logger.debug('Dispatch sync reply: {} - pass'.format(seq))
            self._sync_events[seq].set()

        else:
            # We hope here that this request will not block x_x
            if __debug__:
                logger.debug('Dispatch async reply: {} - start'.format(seq))

            Connection._dispatch_reply(self, seq, raw)

            if __debug__:
                logger.debug('Dispatch async reply: {} - complete'.format(seq))

    def _dispatch_exception(self, seq, raw):
        if __debug__:
            logger.debug('Dispatch exception: {}'.format(seq))

        self._last_recv = time.time()

        sync = None
        _async_callbacks = self._async_callbacks.keys()
        sync = seq not in _async_callbacks
        del _async_callbacks

        if sync:
            self._sync_raw_exceptions[seq] = raw
            if __debug__:
                logger.debug('Dispatch sync exception: {} - pass'.format(seq))
            self._sync_events[seq].set()
        else:
            if __debug__:
                logger.debug('Dispatch async reply: {} - start'.format(seq))
            Connection._dispatch_exception(self, seq, raw)
            if __debug__:
                logger.debug('Dispatch async reply: {} - complete'.format(seq))

    def close(self, _catchall=True):
        with self._close_lock:
            if self._closed:
                return

            self._closed = True

        if __debug__:
            logger.debug('Connection - close - start')

        # Stop dispatch queue first
        self._data_queue.put(None)

        try:
            self._async_request(consts.HANDLE_CLOSE)
        except EOFError, e:
            logger.info(
                'Connection - close - notification failed '
                'because of EOF ({})'.format(e))

        except Exception:
            if not _catchall:
                raise
        finally:
            try:
                self._cleanup(_anyway=True)
            except Exception, e:
                if __debug__:
                    logging.debug('Cleanup exception: {}'.format(e))

                pass

        _sync_events = self._sync_events.keys()
        for lock in _sync_events:
            lock = self._sync_events.get(lock)
            if lock:
                lock.set()

        if __debug__:
            logger.debug('Connection - closed')

    @property
    def inactive(self):
        return time.time() - self._last_recv

    def serve(self, timeout=None):
        raise NotImplementedError('Serve method should not be used!')

    def _init_service_with_notify(self):
        self._init_service()

    def init(self, timeout=60):

        def check_timeout():
            now = time.time()

            logger.debug('Check timeout - start')

            while ( time.time() - now < timeout ) and not self._last_ping and not self.closed:
                time.sleep(1)

            if not self._last_ping:
                logger.info('Check timeout - failed')
                if not self.closed:
                    self.close()
            else:
                logger.debug('Check timeout - ok')

        t = Thread(
            target=check_timeout,
            name="PupyConnection Timeout check"
        )
        t.daemon = True
        t.start()

        self._queue(
            self._on_sync_request_exception, self._init_service_with_notify)

    def loop(self):
        if __debug__:
            logger.debug('Dispatch loop started')

        while not self.closed:
            try:
                self._dispatch()

            except EOFError, e:
                logger.info('Dispatch loop - EOF ({})'.format(e))

            except Exception, e:
                logger.exception(e)
                break

        if __debug__:
            logger.debug('Dispatch loop completed - close connection')

        self.close()

        if __debug__:
            logger.debug('Dispatch loop completed')

    def _serve_loop(self):
        if __debug__:
            logger.debug('Serve loop started')

        while not self.closed:
            try:
                self._serve()
                continue

            except EOFError, e:
                logger.info('Serve loop - EOF ({})'.format(e))

            except Exception, e:
                logger.exception('Exception: {}: {}'.format(type(e), e))

            break

        if __debug__:
            logger.debug('Serve loop completed')

        self.close()

    def _serve(self, timeout=None):
        ''' Check timeouts every serve cycle '''

        interval, ping_timeout = self.get_pings()

        if timeout is None:
            timeout = interval or self._default_serve_timeout

        now = time.time()
        mintimeout = timeout

        data = None

        _async_callbacks = self._async_callbacks.keys()
        for async_event_id in _async_callbacks:
            async_event = self._async_callbacks.get(async_event_id, None)
            if not async_event:
                continue

            if not hasattr(async_event, '_ttl') or not async_event._ttl:
                continue

            if async_event._ttl < now:
                raise EOFError('Async timeout!')

            etimeout = async_event._ttl - now

            if __debug__:
                logger.debug('etimeout = {} / mintimeout = {} / ttl = {}'.format(
                    etimeout, mintimeout, async_event._ttl))

            if mintimeout is None or etimeout < mintimeout:
                mintimeout = etimeout

        timeout = mintimeout

        if __debug__:
            logger.debug('Serve: start / timeout = {} / interval = {} / ping = {} / {}'.format(
                timeout, interval, ping_timeout, self._last_ping))

        data = self._recv(timeout, wait_for_lock = False)

        if __debug__:
            logger.debug('Serve: complete / data = {}'.format(len(data) if data else None))

        self._data_queue.put(data)

        if not data and interval and ping_timeout:
            ping = False
            if not self._last_ping:
                ping = True

            elif now > self._last_ping + interval:
                if __debug__:
                    logger.debug('Send ping, interval: {}, timeout: {}'.format(
                        interval, ping_timeout))

                self._last_ping = self.ping(timeout=ping_timeout, now=now)
            else:
                if __debug__:
                    logger.debug('Ping not required: {} < {}'.format(
                        now, self._last_ping + interval))


    def _dispatch(self):
        if __debug__:
            logger.debug('Dispatch start')

        now = time.time()

        data = self._data_queue.get()
        if data:
            if __debug__:
                logger.debug('Dispatch - data ({})'.format(len(data)))

            msg, seq, args = brine._load(data)
            if msg == consts.MSG_REQUEST:
                if __debug__:
                    logger.debug('Processing message request, type: {} seq: {} - started'.format(
                        args[0], seq))

                self._queue_dispatch_request(seq, args)

            else:
                if __debug__:
                    logger.debug('Processing message response, seq: {} - started'.format(seq))

                if msg == consts.MSG_REPLY:
                    self._dispatch_reply(seq, args)
                elif msg == consts.MSG_EXCEPTION:
                    self._dispatch_exception(seq, args)
                else:
                    raise ValueError("invalid message type: %r" % (msg,))

                if __debug__:
                    logger.debug('Processing message, seq: {} - completed'.format(seq))

            self._last_ping = now

        elif self.closed:
            if __debug__:
                logger.debug('Dispatch interrupt - closed')

            return
        else:
            if __debug__:
                logger.debug('Dispatch - no data')

        _async_callbacks = self._async_callbacks.keys()
        for async_event_id in _async_callbacks:
            async_event = self._async_callbacks.get(async_event_id)
            if not async_event:
                continue

            if not hasattr(async_event, '_ttl'):
                continue

            if async_event._ttl and async_event._ttl < now:
                raise EOFError(
                    'Async timeout! (event={})'.format(async_event),
                    async_event)

    def ping(self, timeout=30, now=None, block=False):
        ''' RPyC do not have any PING handler. So.. why to wait? '''
        now = now or time.time()
        promise = self.async_request(consts.HANDLE_PING, 'ping', timeout=timeout)
        if block:
            promise.wait()

        return now

class PupyConnectionThread(Thread):
    def __init__(self, *args, **kwargs):

        if __debug__:
            logger.debug('Create connection thread')

        self.pupy_srv = args[0]
        self.connection = PupyConnection(*args, **kwargs)

        Thread.__init__(self)
        self.daemon = True
        self.name = "PupyConnection Thread"

        if __debug__:
            logger.debug('Create connection thread completed')

    def run(self):
        if __debug__:
            logger.debug('Run connection thread')

        self.connection.init()
        self.connection.loop()

        if __debug__:
            logger.debug('Connection thread closed')
