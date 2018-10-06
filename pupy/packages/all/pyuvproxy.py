# -*- coding: utf-8 -*-
import rpyc

import pyuv
import struct
import os

os.putenv('UV_THREADPOOL_SIZE', '1')

from netaddr import IPAddress
from threading import Thread, Lock

from socket import inet_ntop
from socket import AF_INET, AF_INET6

from Queue import Queue, Empty

import socket

import errno

import uuid

from network.lib import getLogger
logger = getLogger('pyuvproxy')

CODE_SUCCEEDED, CODE_GENERAL_SRV_FAILURE, CODE_CONN_NOT_ALLOWED, \
    CODE_NET_NOT_REACHABLE, CODE_HOST_UNREACHABLE, CODE_CONN_REFUSED, \
    CODE_TTL_EXPIRED, CODE_COMMAND_NOT_SUPPORTED, \
    CODE_ADDRESS_TYPE_NOT_SUPPORTED, CODE_UNASSIGNED = xrange(10)

ERRNO_TO_SOCKS5 = {
    errno.ECONNREFUSED: CODE_CONN_REFUSED,
    errno.ETIMEDOUT: CODE_CONN_REFUSED,
    errno.EACCES: CODE_CONN_NOT_ALLOWED,
    errno.EAFNOSUPPORT: CODE_ADDRESS_TYPE_NOT_SUPPORTED,
    errno.EPROTOTYPE: CODE_ADDRESS_TYPE_NOT_SUPPORTED,
    errno.EFAULT: CODE_GENERAL_SRV_FAILURE,
    errno.ENETUNREACH: CODE_NET_NOT_REACHABLE,
    -1: CODE_CONN_REFUSED
}

CMD_CONNECT, CMD_BIND, CMD_UDP_ASSOCIATE = xrange(1, 4)

METHOD_NO_AUTH, METHOD_GSSAPI, METHOD_PASSWORD, METHOD_IANA = xrange(4)
METHOD_RESERVED = 0x80
METHOD_NO_ACCEPTABLE_METHOD = 0xFF

ADDR_IPV4, _, ADDR_HOSTNAME, ADDR_IPV6 = xrange(1, 5)


def get_id():
    return '{:012x}'.format(uuid.getnode())


class RpycCommunicationFailed(EOFError):
    pass


class NeighborIsNotExists(ValueError):
    pass


class ConnectionIsNotExists(ValueError):
    pass


class ResourceIsUsed(ValueError):
    pass


class ResourceIsNotExists(ValueError):
    pass


class UndefinedType(ValueError):
    pass


class ChannelIsNotReady(ValueError):
    pass


class Connection(object):
    __slots__ = (
        'neighbor', 'loop', 'virtual_ports',
        'socket', 'local_id', 'remote_id', 'remote_local_address',
        'buffer', 'socks5', 'timer', 'timeout', 'resolving', 'peername'
    )

    def __init__(self, neighbor, remote_id=None, socket=None, buffer=None, socks5=False, timeout=5, peername=None):
        self.neighbor = neighbor
        self.loop = self.neighbor.manager.loop
        self.virtual_ports = self.neighbor.virtual_ports
        self.socket = socket
        self.local_id = hash(self)
        self.remote_id = remote_id
        self.remote_local_address = None
        self.buffer = None
        self.socks5 = socks5
        self.timer = pyuv.Timer(self.loop)
        self.timeout = timeout
        self.resolving = None
        self.peername = peername

    def __repr__(self):
        return 'PYUVC:{}:{}{}'.format(
            self.local_id, self.remote_id,
            '' if not self.peername else ':'+self.peername
        )

    def _connection_timeout(self, handle):
        try:
            if self.resolving:
                self.resolving.cancel()
        except:
            pass

        try:
            handle.stop()
        except:
            pass

        self.close(-1, mutual=self.remote_id is not None)

    def register_remote_id(self, remote_id):
        self.remote_id = remote_id

    def on_connected(self, local_address, error):
        if error:
            try:
                if self.socks5:
                    self.socket.write(
                        struct.pack(
                            'BB', 0x5, ERRNO_TO_SOCKS5.get(
                                error, CODE_GENERAL_SRV_FAILURE)
                        ) + self.socks5[2:])
            except:
                pass

            finally:
                self.close(error, mutual=False)
        else:
            try:
                if self.socks5:
                    addr, port = IPAddress(local_address[0]), local_address[1]
                    self.socket.write(
                        struct.pack(
                            'BBBB', 0x5,
                            0, 0,
                            ADDR_IPV4 if addr.version == 4 else ADDR_IPV6
                        ) + addr.packed + struct.pack('>H', port))

                if self.buffer:
                    self._on_read_data(self.socket, self.buffer, None)

                self.forward()

            except:
                self.close(-1)

    def on_data(self, data):
        if not self.socket:
            logger.debug('Connections(%s) - socket=%s - Not ready',
                self, self.socket)
            raise ChannelIsNotReady(self)

        self.socket.write(data, self._on_send_complete)

    def _on_send_complete(self, handle, error):
        if error:
            self.close(error)

    def on_disconnect(self, reason):
        if not self.socket:
            raise ChannelIsNotReady(self)

        self.close(reason, mutual=False)

    def _on_read_data(self, handle, data, error):
        if data:
            try:
                self.neighbor.callbacks.on_data(
                    self.neighbor.remote_id,
                    self.remote_id,
                    data
                )
            except EOFError:
                self.neighbor.stop(dead=True)
            except:
                self.close(-1)
                raise
        else:
            self.close(error)

    def _on_connected(self, handle, error):
        logger.debug('Connection(%s) - _on_connected (%s)', self, error)

        try:
            if self.timer:
                self.timer.stop()
                self.timer.close()
                self.timer = None
        except:
            pass

        try:
            self.neighbor.callbacks.on_connected(
                self.neighbor.remote_id,
                self.remote_id,
                self.socket.getsockname() if not error else None,
                error=error
            )
            if error:
                try:
                    logger.debug('Connection(%s) - _on_connected - error: %s', self, error)
                    self.socket.close()
                except:
                    pass

            else:
                logger.debug('Connection(%s) - _on_connected - forward', self)
                self.forward()

        except EOFError:
            self.neighbor.stop(dead=True)

    def _virtual_connect(self, port):
        try:
            logger.debug('Connection(%s) - _virtual_connect(%s)', self, port)
            self.socket = self.virtual_ports.connect(port, self.peername)
            logger.debug('Connection(%s) - _virtual_connect(%s) - socket:%s', self, port, self.socket)
            self._on_connected(self.socket, None)
            logger.debug('Connection(%s) - _virtual_connect(%s) - completed', self, port)
        except Exception, e:
            logger.exception('Connection(%s) - _virtual_connect(%s) - exception', self, port)
            self._on_connected(None, e)

    def connect(self, address, dns, bind):
        if type(address) == tuple and address[0] == '254.254.254.254':
            self._virtual_connect(address[1])
            return

        try:
            self.timer.start(self._connection_timeout, self.timeout, 0)

            if type(address) in (str, unicode):
                self.socket = pyuv.Pipe(self.loop, True)
                self.socket.getsockname = lambda: ''

                if os.name == 'nt':
                    self.socket.connect(address, self._on_connected)
                else:
                    if address[0] == '@':
                        address = '\x00' + address[1:]
                    fd = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0)
                    try:
                        fd.setblocking(0)
                        self.socket.open(os.dup(fd.fileno()))
                    except:
                        fd.close()
                        self._on_connected(None, -1)

                self.socket.connect(address, self._on_connected)
            else:
                self.socket = pyuv.TCP(self.loop)
                if bind:
                    if type(bind) in (int, long):
                        bind = ('0.0.0.0', bind)

                    try:
                        self.socket.bind(bind)
                    except:
                        pass

                if dns and len(address) == 2:
                    host, port = address
                    self.resolving = pyuv.dns.getaddrinfo(
                        self.loop,
                        host, port,
                        0, 0, socket.IPPROTO_TCP,
                        callback=self._on_resolved
                    )
                else:
                    self.socket.connect(address, self._on_connected)

        except:
            self._on_connected(None, -1)

    def _on_resolved(self, address, error):
        if error or not address:
            self._on_connected(None, -1)
        else:
            self.socket.connect(address[0][4], self._on_connected)

    def forward(self):
        self.socket.start_read(self._on_read_data)

    def close(self, reason, mutual=True):
        unregistered = False
        if mutual:
            try:
                self.neighbor.callbacks.on_disconnect(
                    self.neighbor.remote_id,
                    self.remote_id,
                    reason
                )

            except EOFError:
                self.neighbor.stop(dead=True)
                unregistered = True

        try:
            self.socket.close()
        except:
            pass

        try:
            if self.timer:
                self.timer.stop()
        except:
            pass

        if not unregistered:
            self.neighbor.unregister_connection(self)


class Acceptor(object):
    def __init__(self, neighbor, local_address, forward_address=None, bind_address=None):
        self.neighbor = neighbor
        self.loop = self.neighbor.manager.loop
        self.local_address = local_address
        self.forward_address = forward_address
        self.bind_address = bind_address
        self.associaction = {}
        if type(local_address) in (str, unicode):
            self.socket = pyuv.Pipe(self.loop, True)
        else:
            self.socket = pyuv.TCP(self.loop)

    def start(self):
        if not os.name == 'nt' and type(self.socket) == pyuv.Pipe:
            try:
                fd = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0)
                if self.local_address[0] == '@':
                    self.local_address = '\x00' + self.local_address[1:]
                fd.bind(self.local_address)
                fd.setblocking(0)
                self.socket.open(os.dup(fd.fileno()))
            finally:
                fd.close()
        else:
            self.socket.bind(self.local_address)

        self.socket.listen(self._on_connection)

    def _on_connection(self, handle, error):
        if error:
            logger.error('_on_connection: %s', error)
            return

        if type(self.socket) == pyuv.TCP:
            client = pyuv.TCP(self.loop)
        else:
            client = pyuv.Pipe(self.loop, True)

        self.socket.accept(client)

        if self.forward_address:
            self.on_connection(client)
        else:
            context = {
                'buffer': [],
                'stage': 0,
                'header': b'',
            }

            client.start_read(
                lambda handle, data, error: self._socks5_read(
                    handle, data, error, context
                ))

    def _socks5_read(self, handle, data, error, context):
        if data:
            context['buffer'].append(data)
            packet = b''.join(context['buffer'])

            if context['stage'] == 0:
                if len(packet) < 2:
                    return

                try:
                    ver, nmethods = struct.unpack_from('BB', packet)
                except:
                    handle.close()
                    return

                if ver != 5:
                    handle.close()
                    return

                if len(packet) < 2 + nmethods:
                    return

                try:
                    methods = struct.unpack_from('B'*nmethods, packet[2:])

                except:
                    handle.close()
                    return

                if METHOD_NO_AUTH not in methods:
                    handle.write(
                        struct.pack('BB', 0x5, METHOD_NO_ACCEPTABLE_METHOD),
                        lambda handle, error: handle.close()
                    )
                    return
                else:
                    handle.write(
                        struct.pack('BB', 0x5, METHOD_NO_AUTH)
                    )
                    context['stage'] += 1
                    context['buffer'] = []

            elif context['stage'] == 1:
                if len(packet) < 4 + 2:
                    return

                try:
                    ver, cmd, rsv, atyp = struct.unpack_from('BBBB', packet)
                except:
                    handle.close()
                    return

                if not all([
                    ver == 5,
                    cmd in (CMD_BIND, CMD_CONNECT, CMD_UDP_ASSOCIATE),
                    rsv == 0,
                    atyp in (ADDR_IPV4, ADDR_HOSTNAME, ADDR_IPV6)
                ]):
                    handle.close()
                    return

                addr_offt = 0
                addr_len = 0

                dns = False

                if atyp == ADDR_IPV4:
                    addr_len = 4
                elif atyp == ADDR_IPV6:
                    addr_len = 16
                elif atyp == ADDR_HOSTNAME:
                    addr_len = ord(packet[4])
                    addr_offt = 1
                    dns = True

                if len(packet) < 4 + 2 + addr_len + addr_offt:
                    return

                context['header'] = packet

                dst_addr = packet[4+addr_offt:4+addr_offt+addr_len]
                dst_port = packet[4+addr_offt+addr_len:4+addr_offt+addr_len+2]

                if atyp == ADDR_IPV4:
                    dst_addr = inet_ntop(AF_INET, dst_addr)
                elif atyp == ADDR_IPV6:
                    dst_addr = inet_ntop(AF_INET6, dst_addr)

                try:
                    dst_port = struct.unpack('>H', dst_port)[0]
                except:
                    handle.close()
                    return

                handle.stop_read()

                self.on_connection(
                    handle, (dst_addr,
                             dst_port), socks5=context['header'], dns=dns
                )

        else:
            handle.close()

    def on_connection(self, client, address=None, buffer=None, socks5=None, dns=False):
        address = address or self.forward_address
        bind = self.bind_address

        peername = client.getpeername()
        if type(peername) in (tuple, list):
            peername = '{}:{}'.format(*peername)
        elif not type(peername) is str:
            peername = str(peername)

        logger.debug('Connection from %s', peername)

        connection = Connection(
            self.neighbor, socket=client, buffer=buffer,
            socks5=socks5, peername=peername
        )

        self.neighbor.register_connection(connection)

        try:
            remote_id = self.neighbor.callbacks.create_connection(
                self.neighbor.remote_id,
                connection.local_id,
                peername
            )

        except EOFError:
            self.neighbor.stop(dead=True)
            return

        connection.register_remote_id(remote_id)

        try:
            self.neighbor.callbacks.connect(
                self.neighbor.remote_id,
                connection.remote_id,
                address,
                dns,
                bind
            )

        except EOFError:
            self.neighbor.stop(dead=True)

    def close(self):
        if type(self.socket) == pyuv.Pipe:
            try:
                if os.path.exists(self.local_address):
                    os.unlink(self.local_address)
            except:
                pass

        self.socket.close()
        self.neighbor.unregister_acceptor(self)


class Callbacks(object):
    def __init__(self, ref):
        self.create_connection = ref['create_connection']
        self.connect = rpyc.async(ref['connect'])
        self.on_connected = rpyc.async(ref['on_connected'])
        self.on_data = rpyc.async(ref['on_data'])
        self.on_disconnect = rpyc.async(ref['on_disconnect'])


class Neighbor(object):
    def __init__(self, manager, callbacks, virtual_ports):
        self.manager = manager
        self.callbacks = Callbacks(callbacks)
        self.connections = {}
        self.acceptors = {}
        self.local_id = None
        self.remote_id = None
        self.virtual_ports = virtual_ports

    def stop(self, dead=False):
        for path_or_port in self.acceptors.keys():
            acceptor = self.acceptors[path_or_port]
            acceptor.close()

        for connection in self.connections.keys():
            self.connections[
                connection
            ].close(-1, mutual=not dead)

        try:
            del self.manager.neighbors[self.local_id]
        except KeyError:
            pass

    def pair(self, local_id, remote_id):
        self.local_id = local_id
        self.remote_id = remote_id

    def get_connection(self, connection_id):
        if connection_id not in self.connections:
            raise ConnectionIsNotExists(connection_id)

        return self.connections[connection_id]

    def create_connection(self, remote_id=None, peername=None):
        connection = Connection(
            self, remote_id=remote_id, peername=peername
        )
        self.register_connection(connection)
        return connection.local_id

    def register_connection(self, connection):
        self.connections[connection.local_id] = connection

    def unregister_connection(self, connection):
        if connection.local_id in self.connections:
            del self.connections[connection.local_id]

    def register_acceptor(self, acceptor, path_or_port):
        self.acceptors[path_or_port] = acceptor

    def unregister_acceptor(self, acceptor_or_path_or_port):
        if type(acceptor_or_path_or_port) in (str, unicode, int):
            try:
                self.acceptors[acceptor_or_path_or_port].close()
                return True

            except:
                return False
        else:
            for k in self.acceptors.keys():
                if self.acceptors[k] == acceptor_or_path_or_port:
                    del self.acceptors[k]
                    return True

        return False

    def uses_port(self, path_or_port):
        return path_or_port in self.acceptors


class VirtualSocket(object):
    __slots__ = (
        'port', 'on_close', 'on_data',
        'on_start_read', 'on_incoming_data',
        'address'
    )

    def __init__(self, port, on_start_read, on_data, on_close, address=None):
        self.port = port
        self.on_close = on_close
        self.on_data = on_data
        self.on_start_read = on_start_read
        self.address = address

        logger.debug('VirtualSocket(%s) - allocated', self)

    def __repr__(self):
        return 'PYUVVS:{}:{}'.format(id(self), self.port)

    def close(self):
        logger.debug('VirtualSocket(%s) - closing', self)

        self.on_close()
        self.on_start_read = None

        logger.debug('VirtualSocket(%s) - closed', self)

    def write(self, data, on_complete):
        logger.debug(
            'VirtualSocket(%s) - writing (%s)', self, len(data))

        try:
            self.on_data(data)
            on_complete(self, None)
        except Exception, e:
            logger.debug(
                'VirtualSocket(%s) - write - exception: %s', self, e)
            on_complete(self, -1)

        logger.debug('VirtualSocket(%s) - written', self)

    def start_read(self, cb):
        logger.debug('VirtualSocket(%s) - activating (cb=%s)', self, cb)
        self.on_start_read(self.address, cb)
        logger.debug('VirtualSocket(%s) - activated', self)

    def getsockname(self):
        return self.address or ('254.254.254.254', self.port)


class VirtualPortsManager(object):
    __slots__ = ('lock', 'ports')

    def __init__(self):
        self.lock = Lock()
        self.ports = {}

    def connect(self, port, peername):
        if port not in self.ports:
            raise ValueError('Port {} is not registered'.format(port))

        logger.debug('VirtualPortsManager: connect(%s)', port)

        try:
            create_connection_cb = self.ports[port]
            on_start_read, on_data, on_close = create_connection_cb(peername)
        except Exception, e:
            logger.exception(e)
            raise

        logger.debug('VirtualPortsManager: connect(%s) - socket created', port)
        return VirtualSocket(port, on_start_read, on_data, on_close)

    def register(self, port, create_cb):
        if port in self.ports:
            raise ValueError('Port {} already registered'.format(port))

        logger.debug('VirtualPortsManager: register(%s)', port)
        self.ports[port] = create_cb

    def unregister(self, port):
        if port not in self.ports:
            raise ValueError('Port {} is not registered'.format(port))

        logger.debug('VirtualPortsManager: unregister(%s)', port)
        del self.ports[port]

    def destroy(self):
        for port in self.ports.keys():
            self.unregister(port)


class Manager(Thread):
    def __init__(self):
        super(Manager, self).__init__()
        self.loop = pyuv.Loop()
        self.neighbors = {}
        self.daemon = True
        self.wake = pyuv.Async(self.loop, self.sync)
        self.queue = Queue()

        self.virtual_ports = VirtualPortsManager()

    def register_virtual_port(self, port, create_virtual_connection_cb):
        logger.debug('Manager: Register virtual port: %s', port)
        self.virtual_ports.register(port, create_virtual_connection_cb)

    def unregister_virtual_port(self, port):
        logger.debug('Manager: Unregister virtual port: %s', port)
        self.virtual_ports.unregister(port)

    def sync(self, handle):
        while True:
            try:
                method, args = self.queue.get_nowait()
            except Empty:
                break

            try:
                method(*args)
            except Exception, e:
                logger.exception(
                    'Defered call exception: %s (ignored)', e)

    def defer(self, method, *args):
        self.queue.put((method, args))
        try:
            self.wake.send()
        except pyuv.error.HandleClosedError:
            pass

    def _stop(self, dead):
        for neighbor_id in self.neighbors.keys():
            self.neighbors[neighbor_id].stop(dead=dead)
        self.wake.close()
        for handle in self.loop.handles:
            if not handle.closed:
                handle.close()

        self.loop.stop()

    def stop(self, dead=False):
        self.defer(self._stop, dead)

    def force_stop(self):
        self.stop(dead=True)

    def run(self):
        try:
            self.loop.run()
        except:
            raise

    def get_neighbor(self, neighbor_id):
        if neighbor_id not in self.neighbors:
            raise NeighborIsNotExists(neighbor_id)

        return self.neighbors[neighbor_id]

    def _bind(self, neighbor_id, local_address, forward, bind):
        neighbor = self.get_neighbor(neighbor_id)
        acceptor = Acceptor(
            neighbor,
            local_address=local_address,
            forward_address=forward,
            bind_address=bind
        )

        if type(local_address) in (str, unicode):
            neighbor.register_acceptor(acceptor, local_address)
        else:
            host, port = local_address
            neighbor.register_acceptor(acceptor, port)

        acceptor.start()

    def bind(self, neighbor_id, local_address=('127.0.0.1', 8080), forward=None, bind=None):
        logger.debug('Manager: bind(%s, %s, %s, %s)',
            neighbor_id, local_address, forward, bind)
        self.defer(self._bind, neighbor_id, local_address, forward, bind)

    def unbind(self, path_or_port):
        logger.debug('Manager: unbind(%s)',
            path_or_port)

        for neighbor in self.neighbors.itervalues():
            if neighbor.unregister_acceptor(path_or_port):
                return True
        return False

    def get_connection(self, neighbor_id, connection_id):
        neighbor = self.get_neighbor(neighbor_id)
        return neighbor.get_connection(connection_id)

    def create_connection(self, neighbor_id, remote_id=None, peername=None):
        logger.debug('Manager: create_connection(%s, %s, %s)',
            neighbor_id, remote_id, peername)

        return self.get_neighbor(
            neighbor_id
        ).create_connection(
            remote_id=remote_id,
            peername=peername
        )

    def connect(self, neighbor_id, connection_id, address, dns, bind=None):
        logger.debug('Manager: connect(%s, %s, %s, %s, %s)',
            neighbor_id, connection_id, address, dns, bind)

        self.defer(
            self.get_neighbor(
                neighbor_id
            ).get_connection(
                connection_id
            ).connect,
            address,
            dns,
            bind
        )

    def forward(self, neighbor_id, connection_id):
        logger.debug('Manager: forward(%s, %s)',
            neighbor_id, connection_id)

        self.defer(
            self.get_neighbor(
                neighbor_id
            ).get_connection(
                connection_id
            ).forward
        )

    def on_connected(self, neighbor_id, connection_id, local_address, error=None):
        logger.debug('Manager: on_connected(%s, %s, %s, %s)',
            neighbor_id, connection_id, local_address, error)

        self.defer(
            self.get_neighbor(
                neighbor_id
            ).get_connection(
                connection_id
            ).on_connected,
            local_address, error
        )

    def on_data(self, neighbor_id, connection_id, data):
        logger.debug('Manager: on_data(%s, %s, %s)',
            neighbor_id, connection_id, len(data))

        self.defer(
            self.get_neighbor(
                neighbor_id
            ).get_connection(
                connection_id
            ).on_data,
            data
        )

    def on_disconnect(self, neighbor_id, connection_id, reason=None):
        logger.debug('Manager: on_disconnect(%s, %s, %s)',
            neighbor_id, connection_id, reason)

        neighbor = self.get_neighbor(
            neighbor_id
        )

        try:
            connection = neighbor.get_connection(
                connection_id
            )

            self.defer(
                connection.on_disconnect,
                reason
            )
        except (ConnectionIsNotExists, ChannelIsNotReady):
            pass

    def get_callbacks(self):
        return {
            'create_connection': self.create_connection,
            'connect': self.connect,
            'on_connected': self.on_connected,
            'on_data': self.on_data,
            'on_disconnect': self.on_disconnect
        }

    def create_neighbor(self, callbacks):
        neighbor = Neighbor(self, callbacks, self.virtual_ports)
        neighbor_id = hash(neighbor)
        self.neighbors[neighbor_id] = neighbor
        return neighbor_id

    def assign_pair_ids(self, local_id, remote_id):
        if local_id not in self.neighbors:
            raise NeighborIsNotExists(local_id)

        self.neighbors[local_id].pair(local_id, remote_id)

    def pair(self, remote_manager):
        remote_id = remote_manager.create_neighbor(self.get_callbacks())
        local_id = self.create_neighbor(remote_manager.get_callbacks())

        remote_manager.assign_pair_ids(remote_id, local_id)
        self.assign_pair_ids(local_id, remote_id)

        return remote_id, local_id

    def _unpair(self, local_id, dead):
        if local_id not in self.neighbors:
            raise NeighborIsNotExists(local_id)

        self.neighbors[local_id].stop(dead=dead)

    def unpair(self, local_id, dead=False):
        self.defer(self._unpair, local_id, dead)

    def list(self, filter_by_local_id=None):
        results = []
        if filter_by_local_id:
            if filter_by_local_id not in self.neighbors:
                return

            neighbor = self.neighbors[filter_by_local_id]
            for port, acceptor in neighbor.acceptors.iteritems():
                results.append([port, acceptor.forward_address or 'socks5'])
        else:
            for neighbor in self.neighbors.itervalues():
                for port, acceptor in neighbor.acceptors.iteritems():
                    results.append(
                        [port, acceptor.forward_address or 'socks5'])

        return results


class PairState(object):
    def __init__(self):
        self.local = None
        self.remote = None
        self.local_id = None
        self.remote_id = None

    def get(self):
        return self.local, self.remote, self.local_id, self.remote_id

    def cleanup(self):
        try:
            if self.local:
                self.local.unpair(self.local_id, dead=True)
        except (ResourceIsNotExists, NeighborIsNotExists):
            pass
        finally:
            self.local = None


class ManagerState(object):
    def __init__(self):
        self.manager = None

    def cleanup(self):
        try:
            if self.manager:
                self.manager.stop()
        except (ResourceIsNotExists, NeighborIsNotExists):
            pass
        finally:
            self.manager = None
