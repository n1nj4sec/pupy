# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
""" abstraction layer over rpyc streams to handle different transports and integrate obfsproxy pluggable transports """

from network.lib import getLogger
logger = getLogger('pss')

__all__ = [
    'PupySocketStream',
]

try:
    import kcp
    assert kcp

    __all__.append(
        'PupyUDPSocketStream'
    )

except ImportError:
    logger.warning('Datagram based stream is not available: KCP missing')

import sys
from rpyc.core import SocketStream, Channel
import socket
import time
import errno
import traceback
import zlib

from rpyc.lib.compat import select, select_error, get_exc_errno

from network.lib.buffer import Buffer

import threading

class addGetPeer(object):
    """ add some functions needed by some obfsproxy transports """
    def __init__(self, peer):
        self.peer=peer

    def getPeer(self):
        return self.peer

class PupyChannel(Channel):
    def __init__(self, *args, **kwargs):
        super(PupyChannel, self).__init__(*args, **kwargs)
        self.compress = True
        self.COMPRESSION_LEVEL = 5
        self.COMPRESSION_THRESHOLD = self.stream.MAX_IO_CHUNK
        self._send_channel_lock = threading.Lock()
        self._recv_channel_lock = threading.Lock()

    def consume(self):
        return self.stream.consume()

    def wake(self):
        return self.stream.wake()

    def recv(self):
        # print "RECV", threading.currentThread()
        with self._recv_channel_lock:
            data = self._recv()

            if __debug__:
                logger.debug('channel: recv=%s', len(data))

            return data

    def send(self, data):
        with self._send_channel_lock:
            if __debug__:
                logger.debug('channel: send=%s', len(data))

            self._send(data)

    def _recv(self):
        """ Recv logic with interruptions """

        # print "RECV! WAIT FOR LENGTH!"

        packet = self.stream.read(self.FRAME_HEADER.size)
        # If no packet - then just return
        if not packet:
            return None

        header = packet

        while len(header) != self.FRAME_HEADER.size:
            packet = self.stream.read(self.FRAME_HEADER.size - len(header))
            if packet:
                header += packet
                del packet

        length, compressed = self.FRAME_HEADER.unpack(header)
        # print "RECV! WAIT FOR LENGTH COMPLETE!"

        required_length = length + len(self.FLUSHER)
        # print "WAIT FOR", required_length

        decompressor = None

        if compressed:
            decompressor = zlib.decompressobj()

        buf = Buffer()

        while required_length:
            packet = self.stream.read(min(required_length, self.COMPRESSION_THRESHOLD))
            if packet:
                required_length -= len(packet)
                # print "GET", len(packet)
                if not required_length:
                    packet = packet[:-len(self.FLUSHER)]

                if compressed:
                    packet = decompressor.decompress(packet)
                    if not packet:
                        continue

                if packet:
                    buf.write(packet)

        if compressed:
            packet = decompressor.flush()
            if packet:
                buf.write(packet)

        # print "COMPLETE!"
        return buf

    def _send(self, data):
        """ Smarter compression support """
        compressed = 0

        ldata = len(data)
        portion = None
        lportion = 0

        # print "SEND .. ", ldata

        if self.compress and ldata > self.COMPRESSION_THRESHOLD:
            portion = data.peek(self.COMPRESSION_THRESHOLD)
            portion = zlib.compress(portion)
            lportion = len(portion)
            if lportion < self.COMPRESSION_THRESHOLD:
                compressed = 1

        if not compressed:
            del portion
            self.stream.write(self.FRAME_HEADER.pack(ldata, compressed), notify=False)
            self.stream.write(data, notify=False)
            self.stream.write(self.FLUSHER)
            # print "SEND .. ", ldata, "DONE"
            return

        del portion

        compressor = zlib.compressobj(self.COMPRESSION_LEVEL)

        total_length = 0
        rest = ldata
        i = 0

        while rest > 0:
            cdata = data.read(self.COMPRESSION_THRESHOLD)

            lcdata = len(cdata)
            rest -= lcdata
            i += lcdata

            portion = compressor.compress(cdata)
            lportion = len(portion)

            if lportion > 0:
                total_length += lportion
                self.stream.write(portion, notify=False)

        portion = compressor.flush()
        lportion = len(portion)
        if lportion:
            total_length += lportion
            self.stream.write(portion, notify=False)

        del portion, data, cdata

        self.stream.insert(self.FRAME_HEADER.pack(total_length, compressed))
        # print "SEND WITH TOTAL LENGTH", total_length
        self.stream.write(self.FLUSHER)

class PupySocketStream(SocketStream):
    def __init__(self, sock, transport_class, transport_kwargs):
        super(PupySocketStream, self).__init__(sock)

        self.MAX_IO_CHUNK = 32000
        self.KEEP_ALIVE_REQUIRED = False
        self.compress = True

        #buffers for transport
        self.upstream = Buffer(
            transport_func=addGetPeer(("127.0.0.1", 443)),
            shared=True
        )

        if sock is None:
            peername = '127.0.0.1', 0
        elif type(sock) is tuple:
            peername = sock[0], sock[1]
        else:
            peername = sock.getpeername()

        self.downstream = Buffer(
            on_write=self._upstream_recv,
            transport_func=addGetPeer(peername),
            shared=True
        )

        self.upstream_lock = threading.Lock()
        self.downstream_lock = threading.Lock()

        self.transport = transport_class(self, **transport_kwargs)

        #buffers for streams
        self.buf_in = Buffer()
        self.buf_out = Buffer()

        self.on_connect()

    def on_connect(self):
        self.transport.on_connect()
        self._upstream_recv()

    def _read(self):
        try:
            buf = self.sock.recv(self.MAX_IO_CHUNK)
            if __debug__:
                logger.debug('stream: read=%s', len(buf) if buf else None)

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

        self.buf_in.write(buf)

    # The root of evil
    def poll(self, timeout):
        if self.closed:
            raise EOFError('polling on already closed connection')
        result = (len(self.upstream)>0 or self.sock_poll(timeout))
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
            if __debug__:
                logger.debug('stream: send=%s', len(self.downstream))

            self.downstream.write_to(super(PupySocketStream, self))

    def waitfor(self, count):
        if __debug__:
            logger.debug('stream: waitfor=%s', count)

        try:
            while len(self.upstream)<count:
                if not self.sock_poll(None) and self.closed:
                    return None

            return self.upstream

        except (EOFError, socket.error):
            self.close()
            raise

        except:
            logger.debug(traceback.format_exc())
            self.close()
            raise

    def read(self, count):
        promise = self.waitfor(count)
        if promise:
            return promise.read(count)

    def insert(self, data):
        with self.upstream_lock:
            self.buf_out.insert(data)

    def flush(self):
        self.buf_out.flush()

    def write(self, data, notify=True):
        if __debug__:
            logger.debug('stream: write=%s / n=%s',
                len(data) if data else None, notify)

        try:
            with self.upstream_lock:
                self.buf_out.write(data, notify)
                del data
                if notify:
                    self.transport.upstream_recv(self.buf_out)
            #The write will be done by the _upstream_recv callback on the downstream buffer

        except (EOFError, socket.error):
            self.close()
            raise

        except:
            logger.debug(traceback.format_exc())
            self.close()
            raise

class PupyUDPSocketStream(object):
    MAGIC = b'\x00'*512

    def __init__(self, sock, transport_class, transport_kwargs={}, client_side=True, close_cb=None, lsi=5):

        if not (type(sock) is tuple and len(sock) in (2,3)):
            raise Exception(
                'dst_addr is not supplied for UDP stream, '
                'PupyUDPSocketStream needs a reply address/port')

        self.client_side = client_side
        self.closed = False

        self.LONG_SLEEP_INTERRUPT_TIMEOUT = lsi
        self.KEEP_ALIVE_REQUIRED = lsi * 3
        self.INITIALIZED = False

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

        self.kcp.window = 32768

        self.buf_in = Buffer(shared=True)
        self.buf_out = Buffer()

        #buffers for transport
        self.upstream = Buffer(
            transport_func=addGetPeer(("127.0.0.1", 443)),
            shared=True
        )

        self.downstream = Buffer(
            on_write=self._send,
            transport_func=addGetPeer(self.dst_addr),
            shared=True
        )

        self.upstream_lock = threading.Lock()
        self.downstream_lock = threading.Lock()

        self.transport = transport_class(self, **transport_kwargs)

        self.MAX_IO_CHUNK = self.kcp.mtu - 24
        self.compress = True
        self.close_callback = close_cb

        self._wake_after = None

        self.on_connect()

    def on_connect(self):
        # Poor man's connection initialization
        # Without this client side bind payloads will not be able to
        # determine when our connection was established
        # So first who knows where to send data will trigger other side as well

        self._emulate_connect()
        self.transport.on_connect()

    def _emulate_connect(self):
        self.kcp.send(self.MAGIC)
        self.kcp.flush()

    def poll(self, timeout):
        if self.closed:
            return None

        return len(self.upstream)>0 or self._poll_read(timeout)

    def close(self):
        if self.close_callback:
            self.close_callback('{}:{}'.format(
                self.dst_addr[0], self.dst_addr[1]))

        self.closed = True
        self.kcp = None

        if self.client_side:
            self.sock.close()

    def _send(self):
        """ called as a callback on the downstream.write """
        if self.closed or not self.kcp:
            raise EOFError('Connection is not established yet')

        if len(self.downstream)>0:
            while len(self.downstream) > 0:
                data = self.downstream.read(self.MAX_IO_CHUNK)
                self.kcp.send(data)

            if self.kcp:
                self.kcp.flush()

    def _poll_read(self, timeout=None):
        if not self.client_side:
            # In case of strage hangups change None to timeout
            self._wake_after = time.time() + timeout
            return self.buf_in.wait(None)

        buf = self.kcp.recv()
        if buf is None:
            if timeout is not None:
                timeout = int(timeout * 1000)

            try:
                buf = self.kcp.pollread(timeout)
            except OSError, e:
                raise EOFError(str(e))

        have_data = False
        while buf is not None:
            if buf:
                if self.INITIALIZED:
                    with self.buf_in:
                        self.buf_in.write(buf, notify=False)
                    have_data = True
                elif buf == self.MAGIC:
                    self.INITIALIZED = True
                else:
                    raise EOFError('Invalid magic')
            else:
                return False

            buf = self.kcp.recv()

        if have_data:
            self.buf_in.flush()
            return True

        return False

    def read(self, count):
        if self.closed:
            return self.upstream.read(count)

        try:
            while len(self.upstream) < count:
                if self.buf_in or self._poll_read(10):
                    with self.buf_in:
                        self.transport.downstream_recv(self.buf_in)
                else:
                    break

            return self.upstream.read(count)

        except:
            logger.debug(traceback.format_exc())

    def insert(self, data):
        with self.upstream_lock:
            self.buf_out.insert(data)

    def flush(self):
        self.buf_out.flush()

    def write(self, data, notify=True):
        # The write will be done by the _upstream_recv
        # callback on the downstream buffer

        try:
            with self.upstream_lock:
                self.buf_out.write(data, notify)
                del data
                if notify:
                    self.transport.upstream_recv(self.buf_out)

        except:
            logger.debug(traceback.format_exc())
            raise

    def consume(self):
        data = False
        with self.downstream_lock:
            while True:
                kcpdata = self.kcp.recv()
                if kcpdata:
                    if self.INITIALIZED:
                        with self.buf_in:
                            self.buf_in.write(kcpdata, notify=False)
                        data = True
                    elif kcpdata == self.MAGIC:
                        self.INITIALIZED = True
                    else:
                        return False
                else:
                    break

            if not data:
                return True

        if data:
            self.buf_in.flush()

        return True

    def wake(self):
        now = time.time()
        if not self._wake_after or (now >= self._wake_after):
            with self.downstream_lock:
                self.buf_in.wake()
            self._wake_after = now + self.LONG_SLEEP_INTERRUPT_TIMEOUT
