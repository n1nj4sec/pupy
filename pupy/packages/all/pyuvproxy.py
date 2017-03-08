# -*- coding: utf-8 -*-
import rpyc

import sys, time
import pyuv
import struct

from netaddr import IPAddress, AddrFormatError
from threading import Event, Thread, Lock
from threading import enumerate as threadenum, current_thread

from socket import AF_INET, AF_INET6, SOCK_DGRAM, SOCK_STREAM
from socket import SOL_SOCKET, SO_REUSEADDR
from socket import SHUT_RD, SHUT_WR
from socket import error as socket_error
from socket import inet_ntop

import socket

import random

import errno

import logging

logging.basicConfig(level=logging.DEBUG)

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
    def __init__(self, neighbor, remote_id=None, socket=None, buffer=None, socks5=False):
        self.neighbor = neighbor
        self.loop = self.neighbor.manager.loop
        self.socket = socket or pyuv.TCP(self.loop)
        self.local_id = hash(self)
        self.remote_id = remote_id
        self.remote_local_address = None
        self.buffer = None
        self.socks5 = socks5

    def register_remote_id(self, remote_id):
        self.remote_id = remote_id

    def on_connected(self, local_address, error):
        if error:
            if self.socks5:
                self.socket.write(
                    struct.pack(
                        'BB', 0x5, ERRNO_TO_SOCKS5.get(reason, CODE_GENERAL_SRV_FAILURE)
                        ) + self.socks5[2:])

            self.close(error, mutual=False)
        else:
            if self.socks5:
                try:
                    addr, port = IPAddress(local_address[0]), local_address[1]

                    self.socket.write(
                        struct.pack(
                            'BBBB', 0x5,
                            0, 0,
                            ADDR_IPV4 if addr.version == 4 else ADDR_IPV6
                            ) + addr.packed + struct.pack('>H', port)
                    )

                except Exception, e:
                    logging.debug('SOCKS5 response failed: {}'.format(e))

            if self.buffer:
                self._on_read_data(self.socket, self.buffer, None)

            self.forward()

    def on_data(self, data):
        if not self.socket:
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
        else:
            self.close(error)

    def _report_close_remote(self, reason):
        self.socket.close()

        try:
            self.neighbor.callbacks.on_disconnect(
                self.neighbor.remote_id,
                self.remote_id,
                reason
            )

        except EOFError:
            self.neighbor.stop(dead=True)

    def _on_connected(self, handle, error):
        try:
           self.neighbor.callbacks.on_connected(
               self.neighbor.remote_id,
               self.remote_id,
               self.socket.getsockname() if not error else None,
               error=error
           )

        except EOFError:
            self.neighbor.stop(dead=True)

        if error:
            self.socket.close()
        else:
            self.forward()

    def _start_connect(self, address):
        self.socket.connect(address, self._on_connected)

    def connect(self, address):
        self.loop.queue_work(lambda: self._start_connect(address))

    def forward(self):
        self.loop.queue_work(lambda: self.socket.start_read(self._on_read_data))

    def close(self, reason, mutual=True):
        if mutual:
            try:
                self.loop.queue_work(lambda: self.socket.shutdown(
                    lambda handle, error: self._report_close_remote(reason)))
            except:
                self.socket.close()
        else:
            self.socket.close()

        self.neighbor.unregister_connection(self)

    def read_exactly(self, size, callback):
        pass


class Acceptor(object):
    def __init__(self, neighbor, local_address, forward_address=None):
        self.neighbor = neighbor
        self.loop = self.neighbor.manager.loop
        self.local_address = local_address
        self.forward_address = forward_address
        self.associaction = {}
        self.socket = pyuv.TCP(self.loop)
        self.socket.bind(local_address)
        self.socket.listen(self._on_connection)

    def _on_connection(self, handle, error):
        if error:
            logging.error('_on_connection: {}'.format(error))
            return

        client = pyuv.TCP(self.loop)

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

                if not METHOD_NO_AUTH in methods:
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

                if atyp == ADDR_IPV4:
                    addr_len = 4
                elif atyp == ADDR_IPV6:
                    addr_len = 16
                elif atyp == ADDR_HOSTNAME:
                    addr_len = ord(header[4])
                    addr_offt = 1

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
                    handle, (dst_addr, dst_port), socks5=context['header']
                )

        else:
            handle.close()

    def on_connection(self, client, address=None, buffer=None, socks5=None):
        address = address or self.forward_address

        connection = Connection(
            self.neighbor, socket=client, buffer=buffer, socks5=socks5
        )

        self.neighbor.register_connection(connection)

        try:
            remote_id = self.neighbor.callbacks.create_connection(
                self.neighbor.remote_id, connection.local_id
            )

        except EOFError:
            self.neighbor.stop(dead=True)
            return

        connection.register_remote_id(remote_id)

        try:
            self.neighbor.callbacks.connect(
                self.neighbor.remote_id,
                connection.remote_id,
                address
            )

        except EOFError:
            self.neighbor.stop(dead=True)

    def close(self):
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
    def __init__(self, manager, callbacks):
        self.manager = manager
        self.callbacks = Callbacks(callbacks)
        self.connections = {}
        self.acceptors = {}
        self.local_id = None
        self.remote_id = None

    def stop(self, dead=False):
        for port in self.acceptors.keys():
            acceptor = self.acceptors[port]
            acceptor.close()

        for connection in self.connections.keys():
            self.connections[
                connection
            ].close(-1, mutual=not dead)

        del self.manager.neighbors[self.local_id]

    def pair(self, local_id, remote_id):
        self.local_id = local_id
        self.remote_id = remote_id

    def get_connection(self, connection_id):
        if not connection_id in self.connections:
            raise ConnectionIsNotExists(connection_id)

        return self.connections[connection_id]

    def create_connection(self, remote_id=None):
        connection = Connection(
            self, remote_id=remote_id
        )
        self.register_connection(connection)
        return connection.local_id

    def register_connection(self, connection):
        self.connections[connection.local_id] = connection

    def unregister_connection(self, connection):
        del self.connections[connection.local_id]

    def register_acceptor(self, acceptor, port):
        self.acceptors[port] = acceptor

    def unregister_acceptor(self, acceptor_or_port):
        if type(acceptor_or_port) == int:
            try:
                self.acceptors[acceptor_or_port].close()
                return True

            except Exception, e:
                return False
        else:
            for k in self.acceptors.keys():
                if self.acceptors[k] == acceptor_or_port:
                    del self.acceptors[k]
                    return True

        return False

    def uses_port(self, port):
        return port in self.acceptors

class Manager(Thread):
    def __init__(self):
        super(Manager, self).__init__()
        self.loop = pyuv.Loop.default_loop()
        self.neighbors = {}
        self.wakeup = Event()
        self.stopped = Event()
        self.ports = {}
        self.daemon = True

    def stop(self, dead=False):
        for neighbor_id in self.neighbors.keys():
            self.neighbors[neighbor_id].stop(dead=dead)

        self.stopped.set()
        self.wakeup.set()

    def force_stop(self):
        self.stop(dead=True)

    def run(self):
        while not self.stopped.is_set():
            self.wakeup.wait()
            if self.stopped.is_set():
                break

            self.wakeup.clear()
            self.loop.run()

    def get_neighbor(self, neighbor_id):
        if not neighbor_id in self.neighbors:
            raise NeighborIsNotExists(neighbor_id)

        return self.neighbors[neighbor_id]

    def bind(self, neighbor_id, host='127.0.0.1', port=8080, forward=None):
        neighbor = self.get_neighbor(neighbor_id)
        acceptor = Acceptor(
            neighbor,
            local_address=(host, port),
            forward_address=forward,
        )

        neighbor.register_acceptor(acceptor, port)

        self.wakeup.set()

    def unbind(self, port):
        for neighbor in self.neighbors.itervalues():
            if neighbor.unregister_acceptor(port):
                return True
        return False

    def get_connection(self, neighbor_id, connection_id):
        neighbor = self.get_neighbor(neighbor_id)
        return neighbor.get_connection(connection_id)

    def create_connection(self, neighbor_id, remote_id=None):
        return self.get_neighbor(
            neighbor_id
        ).create_connection(remote_id=remote_id)

    def connect(self, neighbor_id, connection_id, address):
        self.get_neighbor(
            neighbor_id
        ).get_connection(
            connection_id
        ).connect(address)

        self.wakeup.set()

    def forward(self, neighbor_id, connection_id):
        self.get_neighbor(
            neighbor_id
        ).get_connection(
            connection_id
        ).forward()

        self.wakeup.set()

    def on_connected(self, neighbor_id, connection_id, local_address, error=None):
        connection = self.get_neighbor(
            neighbor_id
        ).get_connection(
            connection_id
        ).on_connected(local_address, error)

    def on_data(self, neighbor_id, connection_id, data):
        self.get_neighbor(
            neighbor_id
        ).get_connection(
            connection_id
        ).on_data(data)

    def on_disconnect(self, neighbor_id, connection_id, reason=None):
        neighbor = self.get_neighbor(
            neighbor_id
        )

        try:
            connection = neighbor.get_connection(
                connection_id
            )

            connection.on_disconnect(reason)
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
        neighbor = Neighbor(self, callbacks)
        neighbor_id = hash(neighbor)
        self.neighbors[neighbor_id] = neighbor
        return neighbor_id

    def assign_pair_ids(self, local_id, remote_id):
        if not local_id in self.neighbors:
            raise NeighborIsNotExists(local_id)

        self.neighbors[local_id].pair(local_id, remote_id)

    def pair(self, remote_manager):
        remote_id = remote_manager.create_neighbor(self.get_callbacks())
        local_id = self.create_neighbor(remote_manager.get_callbacks())

        remote_manager.assign_pair_ids(remote_id, local_id)
        self.assign_pair_ids(local_id, remote_id)

        return remote_id, local_id

    def unpair(self, local_id, dead=False):
        if not local_id in self.neighbors:
            raise NeighborIsNotExists(local_id)

        self.neighbors[local_id].stop(dead=dead)

    def list(self, filter_by_local_id=None):
        results = []
        if filter_by_local_id:
            if not filter_by_local_id in self.neighbors:
                return

            neighbor = self.neighbors[filter_by_local_id]
            for port, acceptor in neighbor.acceptors.iteritems():
                results.append([port, acceptor.forward_address or 'socks5'])
        else:
            for neighbor in self.neighbors.itervalues():
                for port, acceptor in neighbor.acceptors.iteritems():
                    results.append([port, acceptor.forward_address or 'socks5'])

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
