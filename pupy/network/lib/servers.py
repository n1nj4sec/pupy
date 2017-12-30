# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

import sys, logging

from rpyc.utils.server import ThreadedServer
from rpyc.utils.authenticators import AuthenticationError
from rpyc.utils.registry import UDPRegistryClient
from rpyc.core.stream import Stream
from buffer import Buffer

import socket
import select
import errno
import random

from Queue import Queue, Empty
from threading import Thread, RLock

from streams.PupySocketStream import addGetPeer, PupyChannel
from network.lib.connection import PupyConnection, PupyConnectionThread

from network.lib.igd import IGDClient, UPNPError

class PupyTCPServer(ThreadedServer):
    def __init__(self, *args, **kwargs):

        if not "stream" in kwargs:
            raise ValueError("missing stream_class argument")

        if not "transport" in kwargs:
            raise ValueError("missing transport argument")

        self.stream_class = kwargs["stream"]
        self.transport_class = kwargs["transport"]
        self.transport_kwargs = kwargs["transport_kwargs"]
        self.pupy_srv = kwargs["pupy_srv"]

        self.igd_mapping = False
        self.igd = None

        if 'igd' in kwargs:
            self.igd = kwargs['igd']
            del kwargs['igd']

        try:
            ping = self.pupy_srv.config.get('pupyd', 'ping')
            self.ping = ping and ping not in (
                '0', '-1', 'N', 'n', 'false', 'False', 'no', 'No'
            )
        except:
            self.ping = False

        if self.ping:
            try:
                self.ping_interval = int(ping)
            except:
                self.ping_interval = 2

            self.ping_timeout = self.pupy_srv.config.get('pupyd', 'ping_interval')
        else:
            self.ping_interval = None
            self.ping_timeout = None

        del kwargs["stream"]
        del kwargs["transport"]
        del kwargs["transport_kwargs"]
        del kwargs["pupy_srv"]

        ThreadedServer.__init__(self, *args, **kwargs)

        if not self.igd:
            try:
                self.igd = IGDClient()
            except UPNPError as e:
                pass

        if self.igd and self.igd.available:
            try:
                self.igd.AddPortMapping(self.port, 'TCP', self.port)
                self.igd_mapping = True
            except UPNPError as e:
                self.logger.warn(
                    "Couldn't create IGD mapping: {}".format(e.description))


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
                lock, self.pupy_srv,
                self.service,
                PupyChannel(stream),
                ping=self.ping_interval,
                timeout=self.ping_timeout,
                config=config
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

                    interval, timeout = connection.get_pings()

                    while not connection.closed:
                        connection.serve(interval or 10)
                        if interval:
                            connection.ping(timeout=timeout)

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

    def close(self):
        ThreadedServer.close(self)
        if self.igd_mapping:
            try:
                self.igd.DeletePortMapping(self.port, 'TCP')
            except Exception as e:
                self.logger.info('IGD Exception: {}/{}'.format(type(e), e))


class PupyUDPServer(object):
    def __init__(self, service, **kwargs):
        self.kcp = __import__('kcp')

        if not "stream" in kwargs:
            raise ValueError("missing stream_class argument")
        if not "transport" in kwargs:
            raise ValueError("missing transport argument")
        self.stream_class=kwargs["stream"]
        self.transport_class=kwargs["transport"]
        self.transport_kwargs=kwargs["transport_kwargs"]
        self.pupy_srv=kwargs["pupy_srv"]
        del kwargs["stream"]
        del kwargs["transport"]
        del kwargs["transport_kwargs"]
        del kwargs["pupy_srv"]

        ping = self.pupy_srv.config.get('pupyd', 'ping')
        self.ping = ping and ping not in (
            '0', '-1', 'N', 'n', 'false', 'False', 'no', 'No'
        )

        if self.ping:
            try:
                self.ping_interval = int(ping)
            except:
                self.ping_interval = 2

            self.ping_timeout = self.pupy_srv.config.get('pupyd', 'ping_interval')
        else:
            self.ping_interval = None
            self.ping_timeout = None

        self.authenticator=kwargs.get("authenticator", None)
        self.protocol_config=kwargs.get("protocol_config", {})
        self.service=service

        self.active=False
        self.clients = {}
        self.kcps = {}

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
                last_exc = msg
                continue
            break
        self.sock = s
        if self.sock is None:
            raise last_exc

        self.sock.setblocking(0)

    def accept(self):
        try:
            new, updated, failed = self.kcp.dispatch(self.sock.fileno(), 32, self.kcps)
            for f in new:
                self.clients[f] = self.new(f)

            for f in updated:
                self.clients[f].consume()

            for f in failed:
                self.clients[f].close()


        except Exception as e:
            logging.error(e)
            raise

    def on_close(self, addr):
        logging.info("client disconnected: {}".format(addr))
        self.clients[addr].wake()
        del self.clients[addr]
        del self.kcps[addr]

    def new(self, addr):
        host, port=addr[0], addr[1]
        logging.info("new client connected : %s:%s"%(host, port))
        config = dict(
            self.protocol_config,
            credentials=None,
            connid="{}:{}".format(host, port)
        )

        client = self.stream_class(
            (
                self.sock, addr, self.kcps[addr]
            ), self.transport_class, self.transport_kwargs,
            client_side=False, close_cb=self.on_close
        )

        t = PupyConnectionThread(
            self.pupy_srv,
            self.service,
            PupyChannel(client),
            ping=self.ping_interval,
            timeout=self.ping_timeout,
            config=config
        )
        t.daemon=True
        t.start()

        return client

    def start(self):
        self.listen()
        self.active=True
        try:
            while self.active:
                self.accept()
        except EOFError:
            logging.error("EOF")
            pass # server closed by another thread
        except KeyboardInterrupt:
            print("")
            print "keyboard interrupt!"
        except Exception, e:
            logging.exception('Unknown exception {}: {}'.format(type(e), e))
        finally:
            logging.info("server has terminated")
            self.close()

    def close(self):
        self.active = False
        if self.sock:
            self.sock.close()
