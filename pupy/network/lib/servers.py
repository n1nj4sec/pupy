# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

import logging

from rpyc.utils.server import ThreadedServer
from rpyc.utils.authenticators import AuthenticationError

import socket

from Queue import Queue, Empty
from threading import Thread, Lock

from streams.PupySocketStream import PupyChannel
from network.lib.connection import PupyConnection, PupyConnectionThread

from network.lib.igd import UPNPError

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
            self.external = kwargs.get('external', 'igd')
            del kwargs['igd']
        else:
            self.external = kwargs.get('external', kwargs.get('hostname'))

        if 'external' in kwargs:
            del kwargs['external']

        self.external_port = kwargs.get('external_port', kwargs.get('port'))
        if 'external_port' in kwargs:
            del kwargs['external_port']

        if self.pupy_srv:
            try:
                ping = self.pupy_srv.config.get('pupyd', 'ping')
                self.ping = ping and ping not in (
                    '0', '-1', 'N', 'n', 'false', 'False', 'no', 'No'
                )
            except:
                self.ping = False
        else:
            self.ping = False

        if self.ping:
            try:
                self.ping_interval = int(ping)
            except:
                self.ping_interval = 2

            if self.pupy_srv:
                self.ping_timeout = self.pupy_srv.config.get(
                    'pupyd', 'ping_interval')
            else:
                self.ping_timeout = self.ping_interval * 10
        else:
            self.ping_interval = None
            self.ping_timeout = None

        del kwargs["stream"]
        del kwargs["transport"]
        del kwargs["transport_kwargs"]
        del kwargs["pupy_srv"]

        ThreadedServer.__init__(self, *args, **kwargs)

        if self.igd and self.igd.available and self.external != self.host:
            try:
                self.igd.AddPortMapping(
                    self.external_port,
                    'TCP',
                    self.port,
                    intIP=self.host if self.host and not self.host in (
                        '', '0.0.0.0', 'igd'
                    ) else None,
                    desc='pupy'
                )
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
                ping=stream.KEEP_ALIVE_REQUIRED or self.ping_interval,
                timeout=self.ping_timeout,
                config=config
            )

            self.logger.debug('{}:{} Connection complete'.format(h, p))
        finally:
            self.logger.debug('{}:{} Report connection: {}'.format(h, p, connection))
            queue.put_nowait((connection, wrapper, credentials))

    def _authenticate_and_serve_client(self, sock):
        queue = Queue(maxsize=1)
        lock = Lock()

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

                self.logger.debug('Bind server. Serving with interruptions')
                while not connection.closed:
                    self.logger.debug('{}:{} Serving main loop. Inactive: {}'.format(
                        h, p, connection.inactive))

                    with lock:
                        data = connection.serve()

                    connection.dispatch(data)

        except Empty:
            self.logger.debug('{}:{} Timeout'.format(h, p))

        except (EOFError, TypeError):
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
                self.igd.DeletePortMapping(self.external_port, 'TCP')
            except Exception as e:
                self.logger.info('IGD Exception: {}/{}'.format(type(e), e))


class PupyUDPServer(object):
    REQUIRED_KWARGS = [
        'stream', 'transport', 'transport_kwargs',
        'pupy_srv', 'port'
    ]

    def __init__(self, service, **kwargs):
        self.kcp = __import__('kcp')

        for param in self.REQUIRED_KWARGS:
            if not param in kwargs:
                raise ValueError('missing {} argument'.format(param))

            setattr(self, param, kwargs[param])
            del kwargs[param]

        if self.pupy_srv:
            ping = self.pupy_srv.config.get('pupyd', 'ping')
            self.ping = ping and ping not in (
                '0', '-1', 'N', 'n', 'false', 'False', 'no', 'No'
            )
        else:
            self.ping = False

        if self.ping:
            try:
                self.ping_interval = int(ping)
            except:
                self.ping_interval = 2

            if self.pupy_srv:
                self.ping_timeout = self.pupy_srv.config.get('pupyd', 'ping_interval')
            else:
                self.ping_timeout = self.ping_interval * 10
        else:
            self.ping_interval = None
            self.ping_timeout = None

        self.authenticator = kwargs.get('authenticator', None)
        self.protocol_config = kwargs.get('protocol_config', {})
        self.service = service

        self.active = False
        self.clients = {}
        self.sock = None
        self.host = kwargs.get('host') or kwargs.get('hostname')

        self.igd_mapping = False
        self.igd = None

        if 'igd' in kwargs:
            self.igd = kwargs['igd']
            del kwargs['igd']
            self.external = kwargs.get('external', 'igd')
        else:
            self.external = self.host

        if 'external' in kwargs:
            del kwargs['external']

        self.external_port = kwargs.get('external_port', self.port)
        if 'external_port' in kwargs:
            del kwargs['external_port']

        if self.igd and self.igd.available and self.external != self.host:
            try:
                self.igd.AddPortMapping(
                    self.external_port,
                    'UDP',
                    self.port,
                    intIP=self.host if self.host and not self.host in (
                        '', '0.0.0.0', 'igd'
                    ) else None,
                    desc='pupy'
                )
                self.igd_mapping = True
            except UPNPError as e:
                self.logger.warn(
                    "Couldn't create IGD mapping: {}".format(e.description))

        self.LONG_SLEEP_INTERRUPT_TIMEOUT = 5
        self.listen()

    @property
    def stream_class(self):
        return self.stream

    @property
    def transport_class(self):
        return self.transport

    def listen(self):
        s = None
        if not self.host:
            self.host = None

        last_exc = None
        for res in socket.getaddrinfo(
                self.host, self.port, socket.AF_UNSPEC,
                socket.SOCK_DGRAM, 0, socket.AI_PASSIVE):

            af, socktype, proto, canonname, sa = res

            try:
                s = socket.socket(af, socktype, 0)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            except socket.error as msg:
                s = None
                last_exc = msg
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
        self.dispatcher = self.kcp.KCPDispatcher(
            self.sock.fileno(), 0,
            timeout=self.LONG_SLEEP_INTERRUPT_TIMEOUT * 1000
        )

    def on_close(self, addr):
        self.clients[addr].wake()
        del self.clients[addr]
        self.dispatcher.delete(addr)

    def new(self, addr, ckcp):
        logging.info("new client connected: " + addr)

        host, port = addr.rsplit(':', 1)
        port = int(port)

        config = dict(
            self.protocol_config,
            credentials=None,
            connid=addr
        )

        client = self.stream(
            (
                self.sock, (
                    host, port
                ),
                ckcp,
            ),
            self.transport,
            self.transport_kwargs,
            client_side=False,
            close_cb=self.on_close,
            lsi=self.LONG_SLEEP_INTERRUPT_TIMEOUT
        )

        logging.debug('Request pings: {}'.format(
            client.KEEP_ALIVE_REQUIRED or self.ping_interval))

        connthread = PupyConnectionThread(
            self.pupy_srv,
            self.service,
            PupyChannel(client),
            ping=client.KEEP_ALIVE_REQUIRED or self.ping_interval,
            timeout=self.ping_timeout,
            config=config
        )
        connthread.start()
        return connthread.connection

    def start(self):
        self.active=True
        try:
            while self.active:
                try:
                    new, updated, failed = self.dispatcher.dispatch()
                    for f, kcp in new:
                        self.clients[f] = self.new(f, kcp)

                    for f in updated:
                        x = self.clients[f].consume()
                        if not x:
                            failed.add(f)

                    for f in failed:
                        self.clients[f].close()

                    for f in self.dispatcher.keys():
                        if f not in updated:
                            self.clients[f].wake()

                except Exception as e:
                    logging.exception(e)
                    raise

            for f in self.clients.keys():
                self.clients[f].close()

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

        if self.igd_mapping:
            try:
                self.igd.DeletePortMapping(self.external_port, 'UDP')
            except Exception as e:
                logging.info('IGD Exception: {}/{}'.format(type(e), e))
