# -*- encoding: utf-8 -*-

import msgpack
import threading
import socket
import struct
import logging
import time
import errno
import ssl
import urlparse

from network.lib import socks

try:
    from . import getLogger
    logger = getLogger('pproxy')
except:
    logger = logging.getLogger('pproxy')


COMMON_EXCEPTIONS = (
    errno.ECONNREFUSED, errno.ECONNRESET,
    errno.EPIPE, errno.EBADF,
    errno.ETIMEDOUT, errno.EHOSTUNREACH,
    errno.ENETUNREACH, errno.EHOSTDOWN
)

REQUEST_INFO = 0
REQUEST_DNS_LISTENER = 1
REQUEST_TCP_LISTENER = 2
REQUEST_KCP_LISTENER = 3
REQUEST_TLS_LISTENER = 4

class OffloadProxyCommonError(Exception):
    pass

class MsgPackMessages(object):
    def __init__(self, conn):
        self._conn = conn

    def recv(self):
        datalen_b = self._conn.recv(4)
        if datalen_b == '':
            raise EOFError

        datalen, = struct.unpack('>I', datalen_b)
        data = self._conn.recv(datalen)
        return msgpack.loads(data)

    def send(self, msg):
        data = msgpack.dumps(msg)
        datalen = len(data)
        datalen_b = struct.pack('>I', datalen)
        self._conn.sendall(datalen_b + data)

class PupyOffloadDNS(threading.Thread):
    def __init__(self, manager, handler, domain):
        threading.Thread.__init__(self)
        self.daemon = True
        self.active = True
        self.manager = manager
        self.handler = handler
        self.domain = domain
        self._conn = None

        self.cleaner = threading.Thread(target=handler.cleanup)
        self.cleaner.daemon = True

    def run(self):
        self.cleaner.start()

        while self.active:
            try:
                self._serve()

            except EOFError:
                logger.error('DNS: Lost connection (EOF)')
                time.sleep(1)
                continue

            except (socket.error, OSError), e:
                if e.errno in COMMON_EXCEPTIONS:
                    logger.error('DNS: Lost connection (refused)')
                    time.sleep(5)
                    continue

                logger.exception('DNS: Network: %s', e)
                self.active = False

            except Exception, e:
                logger.exception('DNS: %s', e)
                self.active = False

    def _serve(self):
        self._conn = self.manager.request(REQUEST_DNS_LISTENER, self.domain)
        conn = MsgPackMessages(self._conn)
        while self.active:
            request = conn.recv()
            if not request:
                logger.warning('DNS: Recieved empty request. Shutdown')
                self.stop()
                break

            now = time.time()

            response = self.handler.process(request)
            if not response:
                response = []

            used = time.time() - now

            if used > 1:
                logger.warning('DNS: Slow processing speed (%s)s', used)

            conn.send(response)

    def stop(self):
        self.active = False

        if self._conn:
            self._conn.close()
            self._conn = None

        if self.handler:
            self.handler.finished.set()

class PupyOffloadSocket(object):
    def __init__(self, sock, lhost, lport, rhost, rport):
        self._sock = sock
        self._laddr = (lhost, lport)
        self._raddr = (rhost, rport)

    def getsockname(self):
        return self._laddr

    def getpeername(self):
        return self._raddr

    def __getattr__(self, attr):
        if attr in self.__dict__:
            return getattr(self, attr)
        return getattr(self._sock, attr)

class PupyOffloadAcceptor(object):
    def __init__(self, manager, proto, port=None, extra={}):
        self._manager = manager
        self._proto = proto
        self._host = None
        self._port = port
        self._conn = None
        self._extra = extra
        self.active = True

    def bind(self, addr):
        self._host, self._port = addr

    def listen(self, cnt):
        pass

    def settimeout(self, **args):
        pass

    def shutdown(self, arg):
        self.close()

    def close(self, **args):
        self.active = False
        if self._conn:
            self._conn.close()
            self._conn = None

    def accept(self):
        while self.active:
            try:
                self._conn = self._manager.request(self._proto, self._port)

                m = MsgPackMessages(self._conn)
                conninfo = m.recv()

                if conninfo['extra']:
                    data = self._extra[conninfo['data']]
                    m.send(data)
                    conninfo = m.recv()

                return PupyOffloadSocket(
                    self._conn,
                    conninfo['lhost'], conninfo['lport'],
                    conninfo['rhost'], conninfo['rport']
                ), (conninfo['rhost'], conninfo['rport'])

            except (socket.error, OSError), e:
                if e.errno in COMMON_EXCEPTIONS:
                    logger.error('Acceptor (%s): Lost connection (refused)', self._port)
                    time.sleep(5)
                    continue
                else:
                    raise

            except (EOFError, ssl.SSLEOFError):
                logger.error('Acceptor (%s): Lost connection (EOF)', self._port)
                time.sleep(1)
                continue

            except Exception, e:
                logger.exception('Acceptor (%s): Exception: %s', e)
                raise

class PupyOffloadManager(object):
    def __init__(self, server, ca, key, crt, via):
        if ':' in server:
            host, port = server.rsplit(':', 1)
            self._server = (host, int(port))
        elif len(server) == 2:
            self._server = server
        else:
            raise OffloadProxyCommonError('Invalid server specification')

        self._ca = ca
        self._key = key
        self._crt = crt
        self._external_ip = None
        self._ctx = ssl.create_default_context(
            purpose=ssl.Purpose.CLIENT_AUTH,
            cafile=self._ca
        )
        self._ctx.load_cert_chain(self._crt, self._key)
        self._ctx.set_alpn_protocols(['pp/1'])

        if via:
            if '://' not in via:
                raise OffloadProxyCommonError('Proxy argument should be in URI form')
            self._via = urlparse.urlparse(via)
        else:
            self._via = None

        c = self.request(REQUEST_INFO)

        try:
            m = MsgPackMessages(c)
            self._external_ip = m.recv()['ip']

        except Exception, e:
            logger.exception('Communication failed: %s', e)
            raise

        finally:
            c.close()

    def dns(self, handler, domain):
        return PupyOffloadDNS(self, handler, domain)

    def tcp(self, port, extra={}):
        return PupyOffloadAcceptor(self, REQUEST_TCP_LISTENER, port, extra)

    def kcp(self, port, extra={}):
        return PupyOffloadAcceptor(self, REQUEST_KCP_LISTENER, port, extra)

    def ssl(self, port, extra={}):
        return PupyOffloadAcceptor(self, REQUEST_TLS_LISTENER, port, extra)

    @property
    def external(self):
        return self._external_ip

    def request(self, conntype, bind='', timeout=0):
        if self._via:
            proxy = self._via.scheme.upper()
            if proxy == 'SOCKS':
                proxy = 'SOCKS5'

            default_ports = {
                'SOCKS5': 1080,
                'SOCKS4': 1080,
                'HTTP': 3128,
            }

            proxy_type = socks.PROXY_TYPES.get(proxy, 'SOCKS5')
            proxy_addr = self._via.hostname
            proxy_port = self._via.port or default_ports.get(proxy)
            proxy_username = self._via.username or None
            proxy_password = self._via.password or None

            c = socks.create_connection(
                self._server,
                proxy_type, proxy_addr, proxy_port,
                True, proxy_username, proxy_password)
        else:
            c = socket.create_connection(self._server)

        c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        c.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

        if all([hasattr(socket, x) for x in ('TCP_KEEPIDLE', 'TCP_KEEPINTVL', 'TCP_KEEPCNT')]):
            c.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 1 * 60)
            c.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 3  * 60)
            c.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5)

        c = self._ctx.wrap_socket(c)

        m = MsgPackMessages(c)
        m.send({
            'prot': conntype,
            'bind': str(bind),
            'timeout': timeout,
        })
        return c
