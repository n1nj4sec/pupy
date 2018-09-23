# -*- coding: utf-8 -*-

from network.lib import getLogger
logger = getLogger('pvs')

__all__ = [
    'PupyVirtualStream'
]

from network.lib.buffer import Buffer
import threading

import traceback


class PupyVirtualStream(object):

    MAX_IO_CHUNK = 65536
    KEEP_ALIVE_REQUIRED = False
    compress = True

    __slots__ = (
        'upstream', 'on_receive',
        'downstream', 'upstream_lock',
        'downstream_lock', 'transport',
        'transport_class', 'transport_kwargs',
        'buf_in', 'buf_out', 'closed',
        'peername'
    )

    def __init__(self, transport_class, transport_kwargs={}, peername=None, on_receive=None):
        self.on_receive = None
        self.closed = True

        # buffers for transport
        self.upstream = Buffer(shared=True)

        self.downstream = None

        self.upstream_lock = threading.Lock()
        self.downstream_lock = threading.Lock()

        self.transport_class = transport_class
        self.transport_kwargs = transport_kwargs

        # buffers for streams
        self.buf_in = Buffer(shared=True)
        self.buf_out = Buffer()

        self.peername = peername

        if peername and on_receive:
            self.activate(peername, on_receive)

        logger.debug('Allocated (%s)', self)

    def __repr__(self):
        return 'PVS:{}{}'.format(
            str(self.peername) + ':' if self.peername else '',
            id(self))

    def activate(self, peername, on_receive):
        logger.debug('Activating (%s/%s)', self, peername)

        if not self.closed:
            return

        self.closed = False
        self.peername = peername
        self.on_receive = on_receive
        self.downstream = Buffer(
            on_write=self._flush,
            shared=True
        )

        self.transport = self.transport_class(
            self, **self.transport_kwargs)

        logger.debug('Activating ..  (%s) - transport - %s',
            self, self.transport)

        self.transport.on_connect()
        logger.debug('Activated (%s)', self)

    def _flush(self):
        logger.debug('Flush (%s) - %s', self, len(self.downstream))
        data = self.downstream.read()
        try:
            self.on_receive(self, data, None)
            logger.debug('Flush (%s / %d) - complete', self, len(self.downstream))
        except Exception, e:
            logger.exception('Flush (%s) - failed - %d', self, e)
            self.closed = True
            raise EOFError(e)

    def _check_eof(self):
        if self.closed:
            logger.debug('EOF (%s)', self)
            raise EOFError('VirtualStream closed')

    def poll(self, timeout):
        self._check_eof()
        return len(self.upstream)>0 or self._poll_wait(timeout)

    def _poll_wait(self, timeout=None):
        logger.debug('Poll (%s) start (timeout=%s)', self, timeout)

        self._check_eof()
        self.buf_in.wait(timeout)
        self._check_eof()

        result = bool(len(self.buf_in))

        logger.debug('Poll (%s) completed: %s', self, result)
        return result

    def submit(self, data):
        logger.debug('Submit (%s): %s - start', self, len(data))

        try:
            self._check_eof()

            with self.buf_in:
                self.buf_in.write(data)

            logger.debug('Submit (%s): completed', self)

        except Exception, e:
            logger.debug('Submit (%s): exception %s', self, e)
            raise

    def read(self, count):
        logger.debug('Read (%s) - %s / %s - start',
            self, count, len(self.upstream))

        while len(self.upstream) < count and not self.closed:
            if self.buf_in or self.poll(10):
                with self.buf_in:
                    self.transport.downstream_recv(self.buf_in)
            else:
                break

        self._check_eof()

        logger.debug('Read (%s) - %s / %s - done',
            self, count, len(self.upstream))

        return self.upstream.read(count)

    def insert(self, data):
        logger.debug('Insert (%s): %s', self, len(data))

        self._check_eof()

        with self.upstream_lock:
            self.buf_out.insert(data)

    def flush(self):
        logger.debug('Flush (%s)')

        self.buf_out.flush()
        self._check_eof()

    def write(self, data, notify=True):
        logger.debug('Write (%s): %s (notify=%s)',
            self, len(data), notify)

        self._check_eof()

        try:
            with self.upstream_lock:
                self.buf_out.write(data, notify)

                del data

                if notify:
                    self.transport.upstream_recv(self.buf_out)
        except:
            logger.debug(traceback.format_exc())
            raise

    def close(self):
        stack = traceback.extract_stack()
        if len(stack) > 2:
            logger.debug('Close(%s) (at: %s:%s %s(%s))',
                self, *stack[-2])

        self.closed = True
        self.upstream.wake()
