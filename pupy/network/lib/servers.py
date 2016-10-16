# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

import sys, logging

from rpyc.utils.server import ThreadPoolServer, Server
from rpyc.core import Channel, Connection
from rpyc.utils.authenticators import AuthenticationError
from rpyc.utils.registry import UDPRegistryClient
from rpyc.core.stream import Stream
from buffer import Buffer

import socket, time
import errno
import random

try:
    import multiprocessing
    Process=multiprocessing.Process
    Event=multiprocessing.Event
except ImportError: #multiprocessing not available on android ?
    import threading
    Process=threading.Thread
    Event=threading.Event

from streams.PupySocketStream import addGetPeer

class PupyTCPServer(ThreadPoolServer):
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

        ThreadPoolServer.__init__(self, *args, **kwargs)

    def _authenticate_and_build_connection(self, sock):
        '''Authenticate a client and if it succeeds, wraps the socket in a connection object.
        Note that this code is cut and paste from the rpyc internals and may have to be
        changed if rpyc evolves'''
        # authenticate
        addrinfo = sock.getpeername()
        h=addrinfo[0]
        p=addrinfo[1]

        if self.authenticator:
            try:
                sock, credentials = self.authenticator(sock)
            except KeyboardInterrupt:
                pass
            except AuthenticationError:
                self.logger.info("%s:%s failed to authenticate, rejecting connection", h, p)
                return None
        else:
            credentials = None

        # build a connection
        config = dict(self.protocol_config, credentials=credentials, connid="%s:%d"%(h, p))

        def check_timeout(event, cb, timeout=60):
            begin = time.time()
            duration = 0
            while duration < timeout:
                try:
                    time.sleep(timeout - duration)
                except KeyboardInterrupt:
                    pass
                finally:
                    duration = time.time() - begin

            if not event.is_set():
                logging.info("({}:{}) timeout occured ({}) !".format(
                    h, p, duration))
                cb()

        stream = self.stream_class(sock, self.transport_class, self.transport_kwargs)

        event = Event()
        t = Process(target=check_timeout, args=(event, stream.close))
        t.daemon = True
        t.start()

        try:
            c=Connection(self.service, Channel(stream), config=config)
        except KeyboardInterrupt:
            pass
        finally:
            event.set()
            t.terminate()

        return c

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
            t = Process(target = self.handle_new_conn, args=(conn,))
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
