# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
""" abstraction layer over rpyc streams to handle different transports and integrate obfsproxy pluggable transports """

__all__=["PupySocketStream", "PupyUDPSocketStream"]

import sys
from rpyc.core import SocketStream, Connection
from ..buffer import Buffer
import socket
import time
import errno
import logging
import traceback
from rpyc.lib.compat import select, select_error, BYTES_LITERAL, get_exc_errno, maxint
import threading

class addGetPeer(object):
    """ add some functions needed by some obfsproxy transports"""
    def __init__(self, peer):
        self.peer=peer
    def getPeer(self):
        return self.peer

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
        self.on_connect()

        self.MAX_IO_CHUNK=32000

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
        # Just ignore timeout
        result = ( len(self.upstream)>0 or self.sock_poll(timeout) )
        return result

    def sock_poll(self, timeout):
        with self.downstream_lock:
            to_read, _, to_close = select([self.sock], [], [self.sock], timeout)
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
            if len(self.upstream)>=count:
                return self.upstream.read(count)
            while len(self.upstream)<count:
                if not self.sock_poll(None) and self.closed:
                    return None

            return self.upstream.read(count)
        except Exception as e:
            logging.debug(traceback.format_exc())

    def write(self, data):
        try:
            with self.upstream_lock:
                self.buf_out.write(data)
                try:
                    self.transport.upstream_recv(self.buf_out)
                except EOFError as e:
                    logging.debug(traceback.format_exc())
            #The write will be done by the _upstream_recv callback on the downstream buffer
        except Exception as e:
            logging.debug(traceback.format_exc())

class PupyUDPSocketStream(object):
    def __init__(self, sock, transport_class, transport_kwargs={}, client_side=True):
        if not (type(sock) is tuple and len(sock)==2):
            raise Exception("dst_addr is not supplied for UDP stream, PupyUDPSocketStream needs a reply address/port")
        self.client_side=client_side
        self.MAX_IO_CHUNK=40960

        self.sock, self.dst_addr=sock[0], sock[1]
        self.buf_in=Buffer()
        self.buf_out=Buffer()
        #buffers for transport
        self.upstream=Buffer(transport_func=addGetPeer(("127.0.0.1", 443)))

        self.downstream=Buffer(on_write=self._upstream_recv, transport_func=addGetPeer(self.dst_addr))

        self.upstream_lock=threading.Lock()
        self.downstream_lock=threading.Lock()

        self.transport=transport_class(self, **transport_kwargs)
        self.on_connect()
        self.total_timeout=0


    def on_connect(self):
       self.transport.on_connect()

    def poll(self, timeout):
        return len(self.upstream)>0 or self._poll_read(timeout=timeout)

    def close(self):
        pass

    @property
    def closed(self):
        return self.close()

    def _upstream_recv(self):
        """ called as a callback on the downstream.write """
        if len(self.downstream)>0:
            tosend=self.downstream.read()
            sent=self.sock.sendto(tosend, self.dst_addr)
            if sent!=len(tosend):
                print "TODO: error: all was not sent ! tosend: %s sent: %s"%(len(tosend), sent)

    def _poll_read(self, timeout=None):
        if not self.client_side:
            return self.upstream.wait(timeout)
        self.sock.settimeout(timeout)
        try:
            buf, addr=self.sock.recvfrom(self.MAX_IO_CHUNK)
        except socket.timeout:
            self.total_timeout+=timeout
            if self.total_timeout>300:
                self.sock.close() # too much inactivity, disconnect to let it reconnect
            return False
        except socket.error:
            ex = sys.exc_info()[1]
            if get_exc_errno(ex) in (errno.EAGAIN, errno.EWOULDBLOCK):
                # windows just has to be a b**ch
                return True
            self.close()
            raise EOFError(ex)
        if not buf:
            self.close()
            raise EOFError("connection closed by peer")
        self.buf_in.write(BYTES_LITERAL(buf))
        self.total_timeout=0
        return True

    def read(self, count):
        try:
            if len(self.upstream)>=count:
                return self.upstream.read(count)
            while len(self.upstream)<count:
                if self.client_side:
                    with self.downstream_lock:
                        if self._poll_read(0):
                            self.transport.downstream_recv(self.buf_in)
                else:
                    time.sleep(0.0001)

            return self.upstream.read(count)
        except Exception as e:
            logging.debug(traceback.format_exc())

    def write(self, data):
        try:
            with self.upstream_lock:
                self.buf_out.write(data)
                self.transport.upstream_recv(self.buf_out)
            #The write will be done by the _upstream_recv callback on the downstream buffer
        except Exception as e:
            logging.debug(traceback.format_exc())

