# -*- coding: utf-8 -*-
import rpyc

import sys, time
import asyncoro
import struct

from netaddr import IPAddress, AddrFormatError
from threading import Event, Thread, Lock
from threading import enumerate as threadenum, current_thread

from socket import AF_INET, AF_INET6, SOCK_DGRAM, SOCK_STREAM
from socket import SOL_SOCKET, SO_REUSEADDR
from socket import SHUT_RD, SHUT_WR
from socket import error as socket_error
import socket

from netaddr.fbsocket import inet_pton, inet_ntop

import inspect
import types
import traceback

import random

import errno

import traceback

import logging

asyncoro.logger.setLevel(logging.ERROR)

logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger('asyncoroproxy')

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


class NetworkAddress(object):
    def __init__(self, address, family=AF_INET, type=SOCK_STREAM, protocol=0):
        self.family = family
        self.type = type
        self.protocol = protocol
        self.address = address

        if family in (AF_INET, AF_INET6):
            host, port = address
            try:
                address = IPAddress(host)
                port = int(port)
                self.family = AF_INET if address.version == 4 else AF_INET6
            except AddrFormatError:
                pass

    def __eq__(self, another):
        return all(
            hasattr(another, x) and getattr(self, x) == getattr(another, x) for x in [
                'family', 'type', 'protocol', 'address'
            ])

    def socket(self):
        return asyncoro.AsyncSocket(
            socket.socket(self.family, self.type, self.protocol)
        )

    def __repr__(self):
        return '{{Socket Type: {}/{}/{}, Address: {}}}'.format(
            self.family, self.type, self.protocol, self.address
        )


class ExceptionInfo(object):
    def __init__(self, exc_info):
        self.info = exc_info

    def reraise(self):
        logger.debug('Reraising exception: {}/{}/{}'.format(
            self.info[0], self.info[1], self.info[2]
        ))
        raise self.info[0], self.info[1], self.info[2]

    def __repr__(self):
        return '{}: {}'.format(self.info[0], self.info[1])

class RpycCommunicationFailed(EOFError):
    pass

class CallRequest(object):
    def __init__(self, function, args, kwargs, async=False, exception=False):
        self.function = function
        self.args = args
        self.kwargs = kwargs
        self._result = None
        self.async = async
        self.complete = asyncoro.Event() if async else Event()
        self.exception = exception

    def get(self):
        if not self.complete.is_set():
            if self.async:
                yield self.complete.wait()
            else:
                self.complete.wait()

        if isinstance(self._result, ExceptionInfo):
            self._result.reraise()

        yield self._result

    def set(self, value):
        self._result = value
        self.complete.set()
        if isinstance(self._result, ExceptionInfo) and self.exception:
            self._result.reraise()


    def __repr__(self):
        return '<{}:{}({}){}>'.format(
            'A' if self.async else 'S',
            self.function,
            ', '.join(['{}/{}'.format(x, type(x)) for x in self.args]),
            '= {}/{}'.format(
                self._result, type(self._result)
            ) if self.complete.is_set() else ''
        )

class CallInterface(object):
    def __init__(self, callback=False, result=True, bind=None, async=True):
        self.callback = callback
        self.result = result
        self.bind = bind
        self.async = async

__hybrid_interfaces__ = {}

def hybrid(*args, **kwargs):
    def wrapper(fn, **args):
        __hybrid_interfaces__[fn] = CallInterface(**kwargs)
        return fn

    if len(args) == 1 and callable(args[0]):
        return wrapper(args[0])
    else:
        return lambda fn: wrapper(fn, **kwargs)

class HybridControl(object):
    def __init__(self, worker):
        self.worker = worker
        self.coroutine = worker._control

    @property
    def active(self):
        return self.worker.active

    @property
    def servers(self):
        return self.worker.servers

    def __getattr__(self, key):
        if not hasattr(self.worker, key):
            raise AttributeError('No such attribute: {} / class={}'.format(
                key, self.worker.__class__))

        attr = getattr(self.worker, key)

        if not callable(attr):
            return attr

        if not attr.im_func in __hybrid_interfaces__:
            raise AttributeError('Unregistered API call: {}'.format(key))

        key = attr.im_func

        if not self.coroutine:
            raise ResourceIsNotExists('Coroutine not found for class: {}'.format(self.worker))

        async = self.coroutine._scheduler._scheduler == current_thread()

        interface = __hybrid_interfaces__[key]
        if not interface.async:
            return attr

        if not self.worker.active:
            raise ValueError('Calling async methods via stopped control is prohibited')

        if interface.result:
            if async:
                def method(self, *args, **kwargs):
                    req = CallRequest(
                        key,
                        args, kwargs,
                        async=True
                    )
                    self.coroutine.send(req)
                    result = req.get()
                    yield result
            else:
                def method(self, *args, **kwargs):
                    req = CallRequest(
                        key,
                        args, kwargs,
                        async=False
                    )
                    self.coroutine.send(req)
                    result = req.get()
                    if inspect.isgeneratorfunction(attr.im_func):
                        result = next(result)

                    return result
        else:
            def method(self, *args, **kwargs):
                req = CallRequest(
                    key,
                    args, kwargs,
                    async=async,
                    exception=True
                )
                self.coroutine.send(req)

        return types.MethodType(
            types.FunctionType(
                method.func_code,
                method.func_globals,
                key.func_name,
                key.func_defaults,
                method.func_closure
            ),
            self,
            self.__class__
        )

class HybridWorker(object):
    class CleanupExceptions(Exception):
        def __repr__(self):
            return 'Cleanup Exceptions: {}'.format(
                '{}'.format(e) for e in self.args
            )

    def __init__(self):
        super(HybridWorker, self).__init__()
        self.active = True
        self._interface = {}
        self._control = asyncoro.Coro(self._control_coro)
        self._cookie_lock = Lock()
        self._child_coros = []
        logger.debug('New class {}, control coroutine={}'.format(
            self, self._control))

    @property
    def control(self):
        return HybridControl(self)

    def callbacks(self):
        return {
            method.im_func.func_name.strip('_'):(
                getattr(self.control, name),
                __hybrid_interfaces__[method.im_func].bind,
                __hybrid_interfaces__[method.im_func].result,
            ) for name, method in inspect.getmembers(
                self, predicate=inspect.ismethod
            ) if method.im_func in __hybrid_interfaces__ and \
              __hybrid_interfaces__[method.im_func].callback
        }

    def create_cookie(self, dict, value=None, max=sys.maxint):
        with self._cookie_lock:
            while True:
                cookie = random.randint(0, max)
                if not cookie in dict:
                    dict[cookie] = value
                    return cookie

    def delete_cookie(self, dict, cookie):
        with self._cookie_lock:
            if cookie in dict:
                del dict[cookie]

    def _control_coro(self, coro=None):
        logger.debug('Worker for class {}, coroutine={}'.format(self, coro))
        final_exceptions = []

        try:
            while self.active:
                parcel = yield coro.receive()
                try:
                    result = yield parcel.function(
                        self, *parcel.args, **parcel.kwargs
                    )
                    parcel.set(result)
                except Exception, e:
                    logger.info('Exception during call: {}/{}'.format(e, type(e)))
                    exc_info = sys.exc_info()
                    parcel.set(ExceptionInfo(exc_info))

            logger.debug('Worker loop closed for class {}, coroutine={}'.format(
                self, coro))

            self._control = None

        except GeneratorExit:
            logger.debug('Control coroutine {} for class {} terminated'.format(
                coro, self
            ))

        finally:
            if inspect.isgeneratorfunction(self.cleanup):
                # Ignore exceptions during cleanup
                try:
                    yield self.cleanup()
                except Exception, e:
                    exc_info = sys.exc_info()
                    final_exceptions.append(ExceptionInfo(exc_info))
            else:
                # Ignore exceptions during cleanup
                try:
                    self.cleanup()
                except Exception, e:
                    final_exceptions.append(ExceptionInfo(sys.exc_info()))

            logger.debug('Cleanup completed for class {}, coroutine={}'.format(
                self, coro))

        for coro in self._child_coros:
            if coro.is_alive():
                logger.debug('Terminate child coroutine {} for class {}'.format(
                    coro, self
                ))

                try:
                    yield coro.terminate()
                except Exception, e:
                    final_exceptions.append(ExceptionInfo(sys.exc_info()))

                if coro.is_alive():
                    try:
                        yield coro.finish()
                    except Exception, e:
                        final_exceptions.append(ExceptionInfo(sys.exc_info()))

        self._child_coros = []

        logger.debug('Control coroutine exited for class {}, coroutine={}, exceptions={}'.format(
            self, coro, final_exceptions))

        if final_exceptions:
            logger.warning('Cleanup exceptions: {}'.format(final_exceptions))
            raise HybridWorker.CleanupExceptions(final_exceptions)

    def coro(self, *args, **kwargs):
        coro = asyncoro.Coro(*args, **kwargs)
        logger.debug('Created child coroutine {} for class {}'.format(coro, self))
        self._child_coros.append(coro)
        return coro

    def cleanup(self):
        logger.debug('Cleanup request for class {}'.format(self))
        yield

    @hybrid
    def stop(self):
        logger.debug('Stop request for class {}'.format(self))
        self.active = False
        yield True

################################################################################

class Connection(HybridWorker):
    class ConnectionInfo(object):
        def __init__(self, connection):
            self._connection = connection

        @property
        def id(self):
            return self._connection.id

        @property
        def connected(self):
            return self._connection.connecting is None and self.connection_info is not None

        @property
        def connecting(self):
            return self._connection.connecting is not None

        @property
        def closed(self):
            return not self._connection.active

        @property
        def id(self):
            conn_id = self._connection.id
            return (
                (connection_id >> 20) & 0x7FF,
                conn_id & 0xFFFFF
            )

        @property
        def info(self):
            if self.connected:
                return self._connection_info
            elif self.connecting:
                return self._connecting
            else:
                return None

        @property
        def family(self):
            info = self.info
            return info[0] if info else None

        @property
        def type(self):
            info = self.info
            return info[1] if info else None

        @property
        def protocol(self):
            info = self.info
            return info[2] if info else None

    def __init__(self, pair, socket, mtu=4*1024*1024, connection=None):
        super(Connection, self).__init__()
        self.pair = pair
        if connection:
            self.callbacks = pair.callbacks(connection=connection)
        else:
            self.callbacks = pair.callbacks
        self.mtu = mtu
        self.socket = socket
        self.id = self.pair.register_connection(self)
        self.connection_info = None
        self.connecting = None

    def local_reader(self, coro=None):
        logging.debug('Local reader {} for class {}'.format(
            coro, self))
        reason = -1
        try:
            while self.active and self.pair.paired:
                data = yield self.socket.recv(self.mtu)
                if not data:
                    reason = 0
                    break
                else:
                    self.callbacks.data(data)

        except socket_error as e:
            reason = e.args[0]

        except RpycCommunicationFailed:
            reason = -1
            yield self.pair.unpair()

        except Exception:
            reason = -1

        if self.active:
            yield self.control.stop(reason)

        logging.debug('Local reader {} for class {} - exited'.format(
            coro, self))

    def start_reader(self):
        self.coro(self.local_reader)

    @hybrid(result=False)
    def data(self, data):
        try:
            if self.active and self.pair.paired:
                yield self.socket.sendall(data)

        except socket_error as e:
            if self.active:
                yield self.control.stop(e.args[0])

    @hybrid(result=False)
    def close(self):
        self.control.closed(-1)

    @hybrid
    def stop(self, reason=-1, internal=False):
        if internal:
            self.closed(reason)
        else:
            self.control.closed(reason)

        if hasattr(self.callbacks, 'close'):
            try:
                self.callbacks.close(reason)
            except Manager.Pair.CallbackException:
                pass
            except RpycCommunicationFailed:
                yield self.pair.unpair()

        self.connection_info = None
        self.connecting = None

        yield True

    @hybrid(result=False)
    def closed(self, reason):
        self.active = False

    def cleanup(self):
        try:
            self.pair.unregister_connection(self.id)
        finally:
            if hasattr(self.socket, 'shutdown'):
                try:
                    self.socket.shutdown(SHUT_RD)
                except:
                    pass

            self.socket.close()

        yield

class Egress(Connection):
    @hybrid(result=False)
    def connect(self, destination):
        self.socket = destination.socket()

        try:
            self.connecting = [
                destination.family,
                destination.type,
                destination.protocol,
                destination.address,
            ]

            yield self.socket.connect(destination.address)
            localaddr = self.socket.getsockname()

            self.connection_info = self.connecting + [localaddr]
            self.connecting = None

            self.callbacks.connected(localaddr)
            self.start_reader()

        except socket_error as e:
            yield self.stop(e.args[0])

        except Exception as e:
            # Some bug in asyncoro
            if not type(e) == AttributeError:
                logger.exception(e)

            yield self.stop(-1)

class Ingress(Connection):
    def __init__(self, acceptor, sock, address):
        super(Ingress, self).__init__(acceptor.pair, sock)
        self.acceptor = acceptor
        self.address = address

    @hybrid
    def connected(self, destination):
        self.connection_info = self.connecting + [destination]
        self.connecting = None
        self.start_reader()

    @hybrid(result=False)
    def connect(self, destination):
        egress = self.callbacks.create_connection(self.id)
        self.callbacks = self.callbacks(connection=egress)
        self.connecting = [
            destination.family,
            destination.type,
            destination.protocol,
            destination.address,
        ]

        self.callbacks.connect(
            destination.address, destination.family,
            destination.type, destination.protocol
        )

    def cleanup(self):
        yield super(Ingress, self).cleanup()
        if self.address in self.acceptor.clients:
            del self.acceptor.clients[self.address]

class Acceptor(HybridWorker):
    class MissingArguments(Exception):
        def __init__(self, argument):
            super(MissingArguments, self).__init__(argument)
            self.argument = argument

        def __repr__(self):
            return 'Missing argument: {}'.format(self.argument)

    def __init__(self, server, pair, destination, family=None, **kwargs):
        try:
            self.socket = destination.socket()
            self.address = destination.address

            self.socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            self.socket.bind(self.address)
            self.socket.listen(128)

        except:
            self.socket.close()
            raise

        super(Acceptor, self).__init__()

        self.destination = destination
        self.pair = pair
        self.kwargs = kwargs
        self.clients = {}
        self.config = kwargs
        self.server = server
        self.id = pair.register_acceptor(self.control)
        self._coro = self.coro(self._acceptor)
        self.server._acceptors[self.destination] = self.control
        self.exception = None

    def _acceptor(self, coro=None):
        try:
            try:
                while self.active and self.pair.paired:
                    client, address = yield self.socket.accept()
                    ingress = yield self.server.create_client(
                        self, client, address
                    )
                    self.clients[address] = ingress

            except Acceptor.MissingArguments:
                raise

            except socket_error:
                raise

            except Exception, e:
                traceback.print_tb(sys.exc_info()[2])

        except Exception, e:
            self.exception = e

        finally:
            try:
                if self.active:
                    yield self.control.stop()
            except GeneratorExit:
                pass

            if self.pair.unpaired:
                try:
                    yield self.pair.unpair()
                except ResourceIsNotExists:
                    pass
                except GeneratorExit:
                    pass

    def cleanup(self):
        try:
            self.pair.unregister_acceptor(self.id)
            del self.server._acceptors[self.destination]
        finally:
            self.socket.close()

        yield

class ResourceIsUsed(ValueError):
    pass

class ResourceIsNotExists(ValueError):
    pass

class UndefinedType(ValueError):
    pass

class BindServer(HybridWorker):
    def __init__(self):
        super(BindServer, self).__init__()
        self._acceptors = {}

    def create_client(self, acceptor, sock, address):
        raise ValueError('You should override this function!')

    @hybrid
    def bind(self, pair, localaddr, **kwargs):
        for acceptor in self._acceptors:
            if localaddr == acceptor:
                raise ResourceIsUsed('{} already bound'.format(localaddr))

        acceptor = Acceptor(
            self, pair, localaddr, **kwargs
        )

        yield acceptor.id

    @hybrid
    def unbind(self, localaddr):
        if not localaddr in self._acceptors:
            if type(localaddr) == str and ':' in localaddr:
                host, port = localaddr.rsplit(':', 1)
                port = int(port)
                possible = (host, port)
            else:
                possible = localaddr

            for registered in self._acceptors:
                if tuple(registered.address) == tuple(possible):
                    localaddr = registered
                    break

        if not localaddr:
            raise ResourceIsNotExists('{} is not bound'.format(localaddr))

        yield self._acceptors[localaddr].stop()

    @hybrid(async=False)
    def list(self, filter_by_local_id=None):
        return [
            (
                acceptor.pair, acceptor.kwargs, address
            ) for address, acceptor in self._acceptors.iteritems() \
            if not filter_by_local_id or ( filter_by_local_id == acceptor.pair.local)
        ]

    def cleanup(self):
        for localaddr in self._acceptors.keys():
            yield self._acceptors[localaddr].stop()

class ForwardServer(BindServer):
    name = 'FORWARD'

    def create_client(self, acceptor, sock, addr):
        client = Ingress(acceptor, sock, addr)
        yield client.control.connect(acceptor.kwargs['connect'])
        yield client.control

class Socks5Client(Ingress):
    def __init__(self, acceptor, sock, address):
        super(Socks5Client, self).__init__(acceptor, sock, address)
        self._socks5_complete = False
        self._socks5_request_header = None

    @hybrid
    def connected(self, destination):
        addr, port = destination
        addr = IPAddress(addr)
        port = int(port)
        try:
            yield self.socket.sendall(
                struct.pack(
                    'BBBB', 0x5,
                    0, 0,
                    ADDR_IPV4 if addr.version == 4 else ADDR_IPV6
                ) + addr.packed + struct.pack('>H', port)
            )
        except:
            self.control.close()

        self._socks5_complete = True
        super(Socks5Client, self).connected(destination)

    @hybrid(result=False)
    def closed(self, reason):
        if not self._socks5_complete and self._socks5_request_header:
            try:
                yield self.socket.sendall(struct.pack(
                    'BB', 0x5, ERRNO_TO_SOCKS5.get(reason, CODE_GENERAL_SRV_FAILURE)
                ) + self._socks5_request_header[2:])
            except:
                pass

        super(Socks5Client, self).closed(reason)

    @hybrid(result=False)
    def socks5init(self):
        self.coro(self._socks5reader)

    def _socks5reader(self, coro=None):
        header = yield self.socket.recvall(2)

        try:
            ver, nmethods = struct.unpack_from('BB', header)
        except:
            ver, nmethods = None, None

        if ver != 5:
            yield self.control.close()
            return

        try:
            methods = yield self.socket.recvall(nmethods)
        except:
            yield self.control.close()
            return

        try:
            methods = struct.unpack_from('B'*nmethods, methods)
        except:
            yield self.control.close()
            return

        try:
            if not METHOD_NO_AUTH in methods:
                yield self.socket.sendall(
                    struct.pack('BB', 0x5, METHOD_NO_ACCEPTABLE_METHOD)
                )
                yield self.control.close()
                return

            else:
                yield self.socket.sendall(
                    struct.pack('BB', 0x5, METHOD_NO_AUTH)
                )
        except:
            yield self.control.close()
            return

        try:
            header = yield self.socket.recvall(4+2)
            ver, cmd, rsv, atyp = struct.unpack_from('BBBB', header)
        except:
            yield self.control.close()
            return

        if not all([
            ver == 5,
            cmd in (CMD_BIND, CMD_CONNECT, CMD_UDP_ASSOCIATE),
            rsv == 0,
            atyp in (ADDR_IPV4, ADDR_HOSTNAME, ADDR_IPV6)
        ]):
            yield self.control.close()
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

        try:
            rest = yield self.socket.recvall(addr_len+addr_offt)
        except:
            yield self.control.close()
            return

        header += rest

        self._socks5_request_header = header

        dst_addr = header[4+addr_offt:4+addr_offt+addr_len]
        dst_port = header[4+addr_offt+addr_len:4+addr_offt+addr_len+2]

        if atyp == ADDR_IPV4:
            dst_addr = inet_ntop(AF_INET, dst_addr)
        elif atyp == ADDR_IPV6:
            dst_addr = inet_ntop(AF_INET6, dst_addr)

        try:
            dst_port = struct.unpack('>H', dst_port)[0]
        except:
            yield self.control.close()
            return

        yield self.control.connect(
            NetworkAddress((dst_addr, dst_port))
        )

class Socks5Server(BindServer):
    name = 'SOCKS5'

    def create_client(self, acceptor, sock, addr):
        client = Socks5Client(acceptor, sock, addr)
        yield client.control.socks5init()
        yield client.control


################################################################################

class Manager(HybridWorker):
    class Pair(object):
        class CallbackException(Exception):
            def __init__(self, remote_id, *args, **kwargs):
                super(Manager.Pair.CallbackException, self).__init__(
                    *args, **kwargs
                )
                self._remote_id = remote_id

            @property
            def owner(self):
                return self._remote_id

            def __repr__(self):
                return '{{Callback Exception (Remote: {}): {}}}'.format(
                    self._remote_id, super(
                        Manager.Pair.CallbackException, self
                    ).__repr__()
                )

        class Callbacks(object):
            def __init__(self, pair, **bindvars):
                self._callbacks = dict(pair._callbacks)
                self._bind = dict(bindvars)
                self._pair = pair

                self._bind['manager'] = pair.remote

                for name, (method, bind, result) in self._callbacks.iteritems():
                    if bind:
                        if bind in self._bind:
                            self.__bind__(name, method, self._bind[bind])
                    else:
                        setattr(self, name, types.MethodType(
                            lambda *args, **kwargs: __rpyc_method_wrapper__(
                                method, args, kwargs
                            ), self, self.__class__))

            @property
            def available(self):
                return not self._pair._unpaired.is_set()

            def __bind__(self, name, method, arg1):
                setattr(self, name, types.MethodType(
                    lambda self, *args, **kwargs: self.__rpyc_method_wrapper__(
                        method, arg1, *args, **kwargs
                    ),
                    self, self.__class__
                ))

            def __rpyc_method_wrapper__(self, method, *args, **kwargs):
                if self._pair._unpaired.is_set():
                    raise RpycCommunicationFailed(self._pair.remote)

                try:
                    return method(*args, **kwargs)
                #### Some hardcode for rpyc ####
                except EOFError, e:
                    self._pair._unpaired.set()
                    raise Manager.Pair.CallbackException(self._pair.remote, e)

            def __call__(self, **bindargs):
                if self._pair._unpaired.is_set():
                    raise RpycCommunicationFailed(self._pair.remote)

                return Manager.Pair.Callbacks(
                    self._pair, **dict(self._bind, **bindargs)
                )

            def __getitem__(self, item):
                return self._bind.get(item)

            def __repr__(self):
                return '{{Callbacks {} / pair: {} / {}}}'.format(
                    ', '.join([
                        '{}:{}'.format(
                            k, v[0]
                        ) for k,v in self._callbacks.iteritems() if hasattr(self, k)
                    ]),
                    self._pair,
                    ', '.join([
                        '{}={}'.format(k, v) for k,v in self._bind.iteritems()
                    ]))


        def __init__(self, local, callbacks, manager, remote=None):
            self.local = local
            self.remote = remote
            self._connections = {}
            self._acceptors = {}
            self._callbacks = callbacks
            self._cookie_lock = Lock()
            self._unpaired = Event()
            self._manager = manager
            self._unpair_initiated = False

        @property
        def unpaired(self):
            return self._unpaired.is_set()

        @property
        def paired(self):
            return not self._unpaired.is_set()

        @property
        def manager(self):
            return self._manager.control

        def unpair(self):
            if self._unpair_initiated:
                yield

            self._unpair_initiated = True
            yield self.manager.unpair(self.local, dead=self.unpaired)

        def create_cookie(self, dict, value=None, max=sys.maxint):
            with self._cookie_lock:
                while True:
                    cookie = random.randint(0, max)
                    if not cookie in dict:
                        dict[cookie] = value
                        return cookie

        def register_connection(self, coroutine):
            return (self.local << 20) | self.create_cookie(
                self._connections, coroutine, max=0xFFFFF
            )

        def register_acceptor(self, acceptor):
            return (self.local << 20) | self.create_cookie(
                self._acceptors, acceptor, max=0xFFFFF
            )

        def unregister_connection(self, connection_id, stop=False, force=False):
            if connection_id > 0xFFFFF:
                pair_id = (connection_id >> 20) & 0x7FF
                if not pair_id == self.local:
                    raise ResourceIsNotExists(
                        'Connection {} is not registered in this pair: {} != {}'.format(
                            connection_id, pair_id, self.local
                        ))
                connection_id = connection_id & 0xFFFFF

            del self._connections[connection_id]

        def unregister_acceptor(self, acceptor_id, stop=False, force=False):
            if acceptor_id > 0xFFFFF:
                pair_id = (acceptor_id >> 20) & 0x7FF
                if not pair_id == self.local:
                    raise ResourceIsNotExists(
                        'Acceptor {} is not registered in this pair: {} != {}'.format(
                            acceptor_id, pair_id, self.local
                        ))
                acceptor_id = acceptor_id & 0xFFFFF

            del self._acceptors[acceptor_id]

        def stop(self, dead=False):
            dead = dead or self._unpaired.is_set()

            for acceptor_id in self._acceptors.keys():
                acceptor = self._acceptors[acceptor_id]
                if not acceptor.active:
                    continue

                yield acceptor.stop()

            for connection_id in self._connections.keys():
                connection = self._connections[connection_id]

                if not connection.active:
                    continue

                if connection.active:
                    if dead:
                        connection.control.closed(-1)
                    else:
                        yield connection.control.stop()

        @property
        def callbacks(self):
            return Manager.Pair.Callbacks(self)

        @property
        def active(self):
            return (
                x for x in self._connections if x.active
            )

        @property
        def inactive(self):
            return (
                x for x in self._connections if not x.active
            )

        def __repr__(self):
            return '{{L:{} R:{}}}'.format(self.local, self.remote)

    FORWARD, SOCKS5 = xrange(2)

    servers = {
        FORWARD: ForwardServer,
        SOCKS5: Socks5Server,
    }

    def __init__(self):
        super(Manager, self).__init__()
        self._pairs = {}
        self._connections = {}
        self._servers = {}

    def _server_id_to_class_name(self, id):
        if not id in self.servers:
            raise ValueError('Unknown server type = {}'.format(id))

        return str(
            getattr(self.servers[id], 'name', str(type(self.servers[id])))
        )

    @hybrid(callback=True, result=True, bind='manager')
    def ___create_connection(self, remote_id, connection):
        if not remote_id in self._pairs:
            raise ResourceIsNotExists('Unknown pair: {}, known: {}'.format(
                remote_id, self._pairs.keys()
            ))

        pair = self._pairs[remote_id]
        egress = Egress(pair, None, connection=connection).control
        yield egress.id

    @hybrid(callback=True, result=False, bind='connection')
    def ___connect(self, connection, address, family, type, protocol):
        address = NetworkAddress(
            address,
            family=family,
            type=type,
            protocol=protocol,
        )

        try:
            yield self.get_connection(connection).control.connect(address)
        except ResourceIsNotExists:
            logger.debug('Callback: "connect", no such resource. Class: {}'.format(self))

    @hybrid(callback=True, result=False, bind='connection')
    def ___data(self, connection, data):
        try:
            yield self.get_connection(connection).control.data(data)
        except ResourceIsNotExists:
            logger.debug('Callback: "data", no such resource. Class: {}'.format(self))

    @hybrid(callback=True, result=False, bind='connection')
    def ___connected(self, connection, address):
        try:
            yield self.get_connection(connection).control.connected(address)
        except ResourceIsNotExists:
            logger.debug('Callback: "connected", no such resource. Class: {}'.format(self))

    @hybrid(callback=True, result=False, bind='connection')
    def ___close(self, connection, reason):
        try:
            yield self.get_connection(connection).control.closed(reason)
        except ResourceIsNotExists:
            logger.debug('Callback: "close", no such resource. Class: {}'.format(self))
        except Exception as e:
            logger.exception(e)

    @hybrid(callback=True, result=False, bind='connection')
    def ___stop(self, connection):
        if not connection in self._connections:
            raise ValueError('Unknown connection: {}'.format(connection))

        try:
            yield self.get_connection(connection).control.stop()
        except ResourceIsNotExists:
            # Already closed by somebody, who cares
            logger.debug('Callback: "stop", no such resource. Class: {}'.format(self))

    @hybrid
    def bind(self, type, pair_id, netaddress, **config):
        if not type in self.servers:
            raise UndefinedType('Unknown server type {}'.format(type))

        if not pair_id in self._pairs:
            raise ResourceIsNotExists('Unknown pair: {}'.format(pair_id))

        if type not in self._servers:
            self._servers[type] = self.servers[type]().control

        yield self._servers[type].bind(
            self.get_pair(pair_id), netaddress, **config
        )

    @hybrid
    def unbind(self, type, netaddress):
        if not type in self.servers:
            raise UndefinedType('Unregistered server type {}'.format(type))

        yield self._servers[type].unbind(netaddress)

    @hybrid(async=False)
    def list(self, filter_by_local_id=None):
        return [
            (
                type, self._server_id_to_class_name(type), server.list(filter_by_local_id)
            ) for type, server in self._servers.iteritems()
        ]

    @hybrid
    def shutdown(self):
        for server_type in self._servers.keys():
            x = yield self._servers[server_type].stop()

        for pair_id in self._pairs.keys():
            yield self.unpair(pair_id)

        yield self.stop()
        yield True

    def get_connection(self, connection_id):
        pair_id = (connection_id >> 20) & 0x7FF
        connection_id = connection_id & 0xFFFFF

        pair = self.get_pair(pair_id)

        if not connection_id in pair._connections:
            raise ResourceIsNotExists('Connection {} was not found in {}'.format(connection_id, pair_id))

        if not pair._connections[connection_id]:
            raise ResourceIsNotExists('Connection {} in {} was terminated'.format(connection_id, pair_id))

        return pair._connections[connection_id]

    def get_pair(self, pair_id):
        if not pair_id in self._pairs:
            raise ResourceIsNotExists('Unknown pair {}'.format(pair_id))

        return self._pairs[pair_id]

    def create_pair(self, callbacks):
        callbacks = {
            name:(
                rpyc.async(method) if isinstance(
                    method, rpyc.BaseNetref
                ) and result == False else method,
                bind,
                result
            ) for name, (method, bind, result) in callbacks
        }

        cookie = self.create_cookie(self._pairs, max=0x7FF)
        self._pairs[cookie] = Manager.Pair(cookie, callbacks, self)
        return cookie

    def register_pair_peer(self, local, remote):
        self._pairs[local].remote = remote

    def pair(self, manager):
        remote = manager.create_pair(self.callbacks().iteritems())
        local = self.create_pair(manager.callbacks().iteritems())
        self.register_pair_peer(local, remote)
        manager.register_pair_peer(remote, local)
        return local, remote

    @hybrid
    def unpair(self, pair_id, dead=False):
        if not pair_id in self._pairs:
            raise ResourceIsNotExists('Unknown pair {}'.format(pair_id))

        pair = self._pairs[pair_id]
        yield pair.stop(dead=dead)

        del self._pairs[pair_id]

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
            if self.local and self.local.control.active:
            	self.local.control.unpair(self.local_id, dead=True)
        except ResourceIsNotExists:
            pass
        finally:
            self.local = None

class ManagerState(object):
    def __init__(self):
        self.manager = None

    def cleanup(self):
        try:
            if self.manager and self.manager.control.active:
                self.manager.control.shutdown()
        except ResourceIsNotExists:
            pass
        finally:
            self.manager = None
