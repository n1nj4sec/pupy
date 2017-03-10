# -*- coding: utf-8 -*-

import time, logging

from rpyc.core import Connection, consts
from threading import Thread, RLock, Event

class PupyConnection(Connection):
    def __init__(self, lock, pupy_srv, *args, **kwargs):
        self._sync_events = {}
        self._connection_serve_lock = lock
        self._last_recv = time.time()
        kwargs['_lazy'] = True
        Connection.__init__(self, *args, **kwargs)
        if pupy_srv:
            self._local_root.pupy_srv = pupy_srv

    def sync_request(self, handler, *args):
        seq = self._send_request(handler, args)
        logging.debug('Sync request: {}'.format(seq))
        while not ( self._sync_events[seq].is_set() or self.closed ):
            logging.debug('Sync poll until: {}'.format(seq))
            if self._connection_serve_lock.acquire(False):
                try:
                    logging.debug('Sync poll serve: {}'.format(seq))
                    if not self.serve(10):
                        logging.debug('Sync poll serve interrupted: {}/inactive={}'.format(
                            seq, self.inactive))
                finally:
                    logging.debug('Sync poll serve complete. release: {}'.format(seq))
                    self._connection_serve_lock.release()
            else:
                logging.debug('Sync poll wait: {}'.format(seq))
                self._sync_events[seq].wait(timeout=10)

            logging.debug('Sync poll complete: {}/inactive={}'.format(seq, self.inactive))

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
            logging.debug('Async request: {}'.format(seq))
            self._async_callbacks[seq] = async
        else:
            logging.debug('Sync request: {}'.format(seq))
            self._sync_events[seq] = Event()

        self._send(consts.MSG_REQUEST, seq, (handler, self._box(args)))
        return seq

    def _async_request(self, handler, args = (), callback = (lambda a, b: None)):
        self._send_request(handler, args, async=callback)

    def _dispatch_reply(self, seq, raw):
        self._last_recv = time.time()
        sync = seq not in self._async_callbacks
        Connection._dispatch_reply(self, seq, raw)
        if sync:
            if seq in self._sync_events:
                self._sync_events[seq].set()

    def _dispatch_exception(self, seq, raw):
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

        self.connection = PupyConnection(self.lock, *args, **kwargs)
        Thread.__init__(self)
        self.daemon = True

    def run(self):
        try:
            self.connection._init_service()
            with self.lock:
                while not self.connection.closed:
                    self.connection.serve(10)

        except EOFError, TypeError:
            pass
