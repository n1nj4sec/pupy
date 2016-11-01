# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

import sys, logging

from rpyc.utils.server import ThreadedServer
from rpyc.core import Channel, Connection, consts
from rpyc.utils.authenticators import AuthenticationError
from rpyc.utils.registry import UDPRegistryClient
from rpyc.core.stream import Stream
from buffer import Buffer

import socket, time
import errno
import random

from Queue import Queue, Empty
from threading import Thread, Event, RLock

from streams.PupySocketStream import addGetPeer

class PupyConnection(Connection):
    def __init__(self, lock, *args, **kwargs):
        self._sync_events = {}
        self._connection_serve_lock = lock
        self._last_recv = time.time()
        Connection.__init__(self, *args, **kwargs)

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

class PupyTCPServer(ThreadedServer):
    def __init__(self, *args, **kwargs):

        if not "stream" in kwargs:
            raise ValueError("missing stream_class argument")

        if not "transport" in kwargs:
            raise ValueError("missing transport argument")

        self.stream_class = kwargs["stream"]
        self.transport_class = kwargs["transport"]
        self.transport_kwargs = kwargs["transport_kwargs"]

        del kwargs["stream"]
        del kwargs["transport"]
        del kwargs["transport_kwargs"]

        ThreadedServer.__init__(self, *args, **kwargs)

    def _setup_connection(self, lock, sock, queue):
        '''Authenticate a client and if it succeeds, wraps the socket in a connection object.
        Note that this code is cut and paste from the rpyc internals and may have to be
        changed if rpyc evolves'''
        tup = sock.getpeername()
        h, p = tup[0], tup[1] # tup can have different sizes depending on ipv4/ipv6

        credentials = None
        if self.authenticator:
            try:
                wrapper, credentials = self.authenticator(sock)
            except AuthenticationError:
                self.logger.info('{}:{} failed to authenticate, rejecting connection'.format(h, p))
                queue.put_nowait((None, None, None))
                return
        else:
            wrapper = sock

        # build a connection
        config = dict(self.protocol_config, credentials=credentials, connid='{}:{}'.format(h, p))
        stream = self.stream_class(wrapper, self.transport_class, self.transport_kwargs)
        connection = None

        try:
            self.logger.debug('{}:{} Authenticated. Starting connection'.format(h, p))

            connection = PupyConnection(
                lock,
                self.service,
                Channel(stream),
                config=config,
                _lazy=True
            )

            self.logger.debug('{}:{} Connection complete'.format(h, p))
        finally:
            self.logger.debug('{}:{} Report connection: {}'.format(h, p, connection))
            queue.put_nowait((connection, wrapper, credentials))

    def _authenticate_and_serve_client(self, sock):
        queue = Queue(maxsize=1)
        lock = RLock()

        authentication = Thread(target=self._setup_connection, args=(lock, sock, queue))
        authentication.daemon = True
        authentication.start()

        connection = None
        wrapper = None

        tup = sock.getpeername()
        h, p = tup[0], tup[1]

        try:
            self.logger.debug('{}:{} Wait for authentication result'.format(h, p))
            connection, wrapper, credentials = queue.get(block=True, timeout=60)
            self.logger.debug('{}:{} Wait complete: {}'.format(h, p, connection))
            if connection:
                self.logger.debug('{}:{} Initializing service...')
                connection._init_service()
                self.logger.debug('{}:{} Initializing service... complete. Locking')
                with lock:
                    self.logger.debug('{}:{} Serving main loop. Inactive: {}'.format(
                        h, p, connection.inactive))
                    while not connection.closed:
                        connection.serve(10)
        except Empty:
            self.logger.debug('{}:{} Timeout'.format(h, p))

        except EOFError, TypeError:
            pass

        finally:
            self.logger.debug('{}:{} Shutting down'.format(h, p))

            try:
                sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass

            if wrapper:
                wrapper.close()

            self.clients.discard(sock)

class PupyUDPServer(object):
    def __init__(self, service, **kwargs):
        if not "stream" in kwargs:
            raise ValueError("missing stream_class argument")
        if not "transport" in kwargs:
            raise ValueError("missing transport argument")
        self.stream_class=kwargs["stream"]
        self.transport_class=kwargs["transport"]
        self.transport_kwargs=kwargs["transport_kwargs"]
        del kwargs["stream"]
        del kwargs["transport"]
        del kwargs["transport_kwargs"]

        self.authenticator=kwargs.get("authenticator", None)
        self.protocol_config=kwargs.get("protocol_config", {})
        self.service=service

        self.active=False
        self.clients={}
        self.sock=None
        self.hostname=kwargs['hostname']
        self.port=kwargs['port']

    def listen(self):
        s=None
        if not self.hostname:
            self.hostname=None
        last_exc=None
        for res in socket.getaddrinfo(self.hostname, self.port, socket.AF_UNSPEC, socket.SOCK_DGRAM, 0, socket.AI_PASSIVE):
            af, socktype, proto, canonname, sa = res
            try:
                s = socket.socket(af, socktype, proto)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            except socket.error as msg:
                s = None
                last_exc=msg
                continue
            try:
                s.bind(sa)
            except socket.error as msg:
                s.close()
                s = None
                last_exc=msg
                continue
            break
        self.sock=s
        if self.sock is None:
            raise last_exc

    def accept(self):
        try:
            data, addr = self.sock.recvfrom(40960)
            if data:
                self.dispatch_data(data, addr)
            else:
                self.clients[addr].close()
        except Exception as e:
            logging.error(e)

    def dispatch_data(self, data_received, addr):
        host, port=addr[0], addr[1]
        if addr not in self.clients:
            logging.info("new client connected : %s:%s"%(host, port))
            config = dict(self.protocol_config, credentials=None, connid="%s:%d"%(host, port))
            if self.authenticator:
                try:
                    sock, credentials = self.authenticator(data_received)
                    config["credentials"]=credentials
                except AuthenticationError:
                    logging.info("failed to authenticate, rejecting data")
                    raise
            self.clients[addr]=self.stream_class((self.sock, addr), self.transport_class, self.transport_kwargs, client_side=False)
            conn=Connection(self.service, Channel(self.clients[addr]), config=config, _lazy=True)
            t = Thread(target = self.handle_new_conn, args=(conn,))
            t.daemon=True
            t.start()
        with self.clients[addr].downstream_lock:
            self.clients[addr].buf_in.write(data_received)
            self.clients[addr].transport.downstream_recv(self.clients[addr].buf_in)

    def handle_new_conn(self, conn):
        try:
            conn._init_service()
            conn.serve_all()
        except Exception as e:
            logging.error(e)

    def start(self):
        self.listen()
        self.active=True
        try:
            while self.active:
                self.accept()
        except EOFError:
            pass # server closed by another thread
        except KeyboardInterrupt:
            print("")
            print "keyboard interrupt!"
        finally:
            logging.info("server has terminated")
            self.close()

    def close(self):
        self.active=False
        self.sock.close()
