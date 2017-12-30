# -*- coding: utf-8 -*-

import time, logging

from rpyc.core import Connection, consts
from threading import Thread, RLock, Event

DEBUG_NETWORK=False

class PupyConnection(Connection):
    def __init__(self, lock, pupy_srv, *args, **kwargs):
        self._sync_events = {}
        self._connection_serve_lock = lock
        self._last_recv = time.time()
        self._ping = False
        self._ping_timeout = 2
        self._serve_timeout = 10

        if 'ping' in kwargs:
            ping = kwargs.get('ping')
            del kwargs['ping']
        else:
            ping = None

        if 'timeout' in kwargs:
            timeout = kwargs.get('timeout')
            del kwargs['timeout']
        else:
            timeout = None

        if ping or timeout:
            self.set_pings(ping, timeout)

        kwargs['_lazy'] = True
        Connection.__init__(self, *args, **kwargs)
        if pupy_srv:
            self._local_root.pupy_srv = pupy_srv

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
        if DEBUG_NETWORK:
            logging.debug('Sync request: {}'.format(seq))
        while not ( self._sync_events[seq].is_set() or self.closed ):
            if DEBUG_NETWORK:
                logging.debug('Sync poll until: {}'.format(seq))
            if self._connection_serve_lock.acquire(False):
                try:
                    if DEBUG_NETWORK:
                        logging.debug('Sync poll serve: {}'.format(seq))
                    if not self.serve(self._serve_timeout):
                        if DEBUG_NETWORK:
                            logging.debug('Sync poll serve interrupted: {}/inactive={}'.format(
                                seq, self.inactive))
                        if self._ping:
                            self.ping(timeout=self._ping_timeout)

                finally:
                    if DEBUG_NETWORK:
                        logging.debug('Sync poll serve complete. release: {}'.format(seq))
                    self._connection_serve_lock.release()
            else:
                if DEBUG_NETWORK:
                    logging.debug('Sync poll wait: {}'.format(seq))
                self._sync_events[seq].wait(timeout=self._serve_timeout)
                if self._ping:
                    self.ping(timeout=self._ping_timeout)

            if DEBUG_NETWORK:
                logging.debug('Sync poll complete: {}/inactive={}'.format(seq, self.inactive))

        if DEBUG_NETWORK:
            logging.debug('Sync request handled: {}'.format(seq))

        if seq in self._sync_events:
            del self._sync_events[seq]

        if self.closed:
            raise EOFError()

        isexc, obj = self._sync_replies.pop(seq)
        if isexc:
            raise obj
        else:
            return obj

    def _send_request(self, handler, args, async=None):
        seq = next(self._seqcounter)
        if async:
            if DEBUG_NETWORK:
                logging.debug('Async request: {}'.format(seq))
            self._async_callbacks[seq] = async
        else:
            if DEBUG_NETWORK:
                logging.debug('Sync request: {}'.format(seq))
            self._sync_events[seq] = Event()

        self._send(consts.MSG_REQUEST, seq, (handler, self._box(args)))

        if DEBUG_NETWORK:
            logging.debug('Request submitted: {}'.format(seq))

        return seq

    def _async_request(self, handler, args = (), callback = (lambda a, b: None)):
        self._send_request(handler, args, async=callback)

    def _dispatch_reply(self, seq, raw):
        if DEBUG_NETWORK:
            logging.debug('Dispatch reply: {}'.format(seq))

        self._last_recv = time.time()
        sync = seq not in self._async_callbacks
        Connection._dispatch_reply(self, seq, raw)
        if sync:
            if seq in self._sync_events:
                self._sync_events[seq].set()

    def _dispatch_exception(self, seq, raw):
        if DEBUG_NETWORK:
            logging.debug('Dispatch exception: {}'.format(seq))

        self._last_recv = time.time()
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

class PupyConnectionThread(Thread):
    def __init__(self, *args, **kwargs):
        if hasattr(kwargs, 'lock'):
            self.lock = getattr(kwargs, 'lock')
            del kwargs['lock']
        else:
            self.lock = RLock()

        if DEBUG_NETWORK:
            logging.debug('Create connection thread')

        self.connection = PupyConnection(self.lock, *args, **kwargs)
        Thread.__init__(self)
        self.daemon = True

        if DEBUG_NETWORK:
            logging.debug('Create connection thread completed')


    def run(self):
        if DEBUG_NETWORK:
            logging.debug('Run connection thread')

        try:
            if DEBUG_NETWORK:
                logging.debug('Init connection')

            self.connection._init_service()

            if DEBUG_NETWORK:
                logging.debug('Init connection complete. Acquire lock')

            with self.lock:
                if DEBUG_NETWORK:
                    logging.debug('Start serve loop')

                while not self.connection.closed:
                    self.connection.serve(10)

        except EOFError, TypeError:
            pass
