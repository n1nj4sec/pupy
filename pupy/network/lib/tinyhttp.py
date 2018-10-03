# -*- coding: utf-8 -*-

__all__ = ['HTTP']

import urllib2
import urllib
import urlparse
import httplib
import ssl
import socket
import types

import StringIO

from . import socks

from poster.streaminghttp import StreamingHTTPConnection, StreamingHTTPSConnection
from poster.streaminghttp import StreamingHTTPHandler, StreamingHTTPSHandler
from poster.encode import multipart_encode


def merge_dict(a, b):
    d = a.copy()
    d.update(b)
    return d

## Fix poster bug

class NoRedirects(urllib2.HTTPErrorProcessor):
    __slots__ = ()

    def http_response(self, request, response):
        return response

    https_response = http_response

class NullConnection(httplib.HTTPConnection):
    __slots__ = ('sock', 'timeout')

    def __init__(self, socket, timeout, *args, **kwargs):
        httplib.HTTPConnection.__init__(self, *args, **kwargs)
        self.sock = socket
        self.timeout = timeout

    def connect(self):
        self.sock.settimeout(self.timeout)

class NullHandler(urllib2.HTTPHandler):
    __slots__ = ('table', 'lock')

    def __init__(self, table, lock):
        urllib2.HTTPHandler.__init__(self)
        self.table = table
        self.lock = lock

    def http_open(self, req):
        def build(host, port=None, strict=None, timeout=0):
            with self.lock:
                return NullConnection(self.table[host], timeout, host)

        return self.do_open(build, req)

class NETFile(StringIO.StringIO):
    __slots__ = ()

class UDPReaderHandler(urllib2.BaseHandler):
    __slots__ = ('sock', 'timeout')

    def udp_open(self, req):
        url = urlparse.urlparse(req.get_full_url())
        host = url.hostname
        port = url.port or 123

        data = []
        conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
        conn.connect((host, port))
        conn.settimeout(10)

        try:
            if url.path:
                conn.send(url.path[1:])

            data = conn.recv(4096)
            if not data:
                raise ValueError('No data')

        except:
            pass

        finally:
            conn.close()

        fp = NETFile(data)
        if data:
            headers = {
                'Content-type': 'application/octet-stream',
                'Content-length': len(data),
            }
            code = 200
        else:
            headers = {}
            code = 404

        return urllib.addinfourl(fp, headers, req.get_full_url(), code=code)


class TCPReaderHandler(urllib2.BaseHandler):
    __slots__ = ('sslctx')

    def __init__(self, context=None, *args, **kwargs):
        if context:
            self.sslctx = context
        else:
            self.sslctx = ssl.create_default_context()
            self.sslctx.check_hostname = False
            self.sslctx.verify_mode = ssl.CERT_NONE

    def do_stream_connect(self, req):
        url = urlparse.urlparse(req.get_full_url())
        host = url.hostname
        port = url.port or 53

        conn = socket.create_connection((host, port))
        conn.settimeout(10)
        return conn

    def tls_open(self, req):
        conn = self.do_stream_connect(req)
        conn = self.sslctx.wrap_socket(
            conn, server_hostname=req.get_host())
        return self._get_stream_data(conn, req)

    def tcp_open(self, req):
        conn = self.do_stream_connect(req)
        return self._get_stream_data(conn, req)

    def _get_stream_data(self, conn, req):
        data = []
        url = urlparse.urlparse(req.get_full_url())

        try:
            if url.path:
                conn.send(url.path[1:])

            while True:
                b = conn.recv(65535)
                if not b:
                    break

                data.append(b)

            if not data:
                raise ValueError('No data')

        except:
            pass

        finally:
            conn.close()

        data = b''.join(data)

        fp = NETFile(data)
        if data:
            headers = {
                'Content-type': 'application/octet-stream',
                'Content-length': len(data),
            }
            code = 200
        else:
            headers = {}
            code = 404

        return urllib.addinfourl(fp, headers, req.get_full_url(), code=code)

StreamingHTTPSHandler.https_open = lambda self, req: self.do_open(
    StreamingHTTPSConnection, req, context=self._context)

class SocksiPyConnection(StreamingHTTPConnection):
    __slots__ = ('proxyargs', 'sock')

    def __init__(self, proxytype, proxyaddr, proxyport=None, rdns=True, username=None, password=None, *args, **kwargs):
        self.proxyargs = (proxytype, proxyaddr, proxyport, rdns, username, password)
        httplib.HTTPConnection.__init__(self, *args, **kwargs)

    def connect(self):
        if self.sock is None:
            self.sock = socks.socksocket()
            self.sock.setproxy(*self.proxyargs)
            if isinstance(self.timeout, float):
                self.sock.settimeout(self.timeout)
            self.sock.connect((self.host, self.port))

class SocksiPyConnectionS(StreamingHTTPSConnection):
    __slots__ = ('proxyargs', 'sock')

    def __init__(self, proxytype, proxyaddr, proxyport=None, rdns=True, username=None, password=None, *args, **kwargs):
        self.proxyargs = (proxytype, proxyaddr, proxyport, rdns, username, password)
        httplib.HTTPSConnection.__init__(self, *args, **kwargs)

    def connect(self):
        if self.sock is None:
            sock = socks.socksocket()
            sock.setproxy(*self.proxyargs)
            if type(self.timeout) in (int, float):
                sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))

            if self._tunnel_host:
                server_hostname = self._tunnel_host
            else:
                server_hostname = self.host

            self.sock = self._context.wrap_socket(
                sock, server_hostname=server_hostname)

class SocksiPyHandler(urllib2.HTTPHandler, urllib2.HTTPSHandler, TCPReaderHandler):
    __slots__ = ('args', 'kw')

    def __init__(self, *args, **kwargs):
        self.args = args
        self.kw = kwargs
        urllib2.HTTPHandler.__init__(self)

    def http_open(self, req):
        def build(host, port=None, strict=None, timeout=0):
            if 'context' in self.kw:
                kw = {
                    x:y for x,y in self.kw.iteritems() if x not in ('context')
                }
            else:
                kw = self.kw

            conn = SocksiPyConnection(*self.args, host=host, port=port, strict=strict, timeout=timeout, **kw)
            return conn

        return self.do_open(build, req)

    def https_open(self, req):
        def build(host, port=None, timeout=0, **kwargs):
            kw = merge_dict(self.kw, kwargs)
            conn = SocksiPyConnectionS(*self.args, host=host, port=port, timeout=timeout, **kw)
            return conn

        return self.do_open(build, req)

    def do_stream_connect(self, req):
        url = urlparse.urlparse(req.get_full_url())
        host = url.hostname
        port = url.port or 53
        conn = SocksiPyConnection(*self.args, host=host, port=port, timeout=15)
        conn.connect()
        return conn.sock

class HTTP(object):

    __slots__ = ('ctx', 'proxy', 'noverify', 'timeout', 'opener')

    def __init__(self, proxy=None, noverify=True, follow_redirects=False, headers={}, timeout=5, cadata=None):
        self.ctx = ssl.create_default_context(cadata=cadata)

        if noverify:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

        self.proxy = None

        tproxy = type(proxy)
        if tproxy in (str, unicode):
            proxyscheme = urlparse.urlparse(proxy)
            scheme = proxyscheme.scheme.upper()
            if scheme == 'SOCKS':
                scheme = 'SOCKS5'

            self.proxy = scheme, proxyscheme.hostname+(
                ':'+str(proxyscheme.port) if proxyscheme.port else ''), \
                proxyscheme.username or None, \
                proxyscheme.password or None
        elif proxy in (True, None):
            self.proxy = find_default_proxy()
        elif hasattr(proxy, 'as_tuple'):
            self.proxy = proxy.as_tuple()
        else:
            self.proxy = proxy

        self.noverify = noverify
        self.timeout = timeout

        if not self.proxy:
            handlers = [
                StreamingHTTPHandler,
                StreamingHTTPSHandler(context=self.ctx),
                TCPReaderHandler(context=self.ctx)
            ]
        else:
            scheme, host, user, password = self.proxy

            scheme = socks.PROXY_TYPES[scheme]
            port = socks.DEFAULT_PORTS[scheme]

            if ':' in host:
                host, maybe_port = host.split(':')

                try:
                    port = int(maybe_port)
                except ValueError:
                    pass

            sockshandler = SocksiPyHandler(
                scheme, host, port,
                user or None, password or None,
                context=self.ctx if self.noverify else None
            )

            handlers = []
            if scheme == socks.HTTP:
                http_proxy = '{}:{}'.format(host, port)

                if user and password:
                    http_proxy = '{}:{}@{}'.format(user, password, http_proxy)

                http_proxy = 'http://' + http_proxy

                handlers.append(urllib2.ProxyHandler({
                    'http': http_proxy}))
                handlers.append(StreamingHTTPHandler)

            handlers.append(sockshandler)

        if not follow_redirects:
            handlers.append(NoRedirects)

        handlers.append(UDPReaderHandler)

        self.opener = urllib2.OpenerDirector()
        for h in handlers:
            if isinstance(h, (types.ClassType, type)):
                h = h()
            self.opener.add_handler(h)

        if type(headers) == dict:
            self.opener.addheaders = [
                (x, y) for x,y in headers.iteritems()
            ]
        else:
            self.opener.addheaders = headers

    def get(self, url, save=None, headers=None, return_url=False, return_headers=False, code=False):
        if headers:
            url = urllib2.Request(url, headers=headers)

        response = self.opener.open(url, timeout=self.timeout)
        result = []

        if save:
            with open(save, 'w+b') as output:
                while True:
                    chunk = response.read(65535)
                    if not chunk:
                        break

                    output.write(chunk)

            result = [save]
        else:
            result = [response.read()]

        if return_url:
            result.append(response.url)

        if code:
            result.append(response.code)

        if return_headers:
            result.append(response.info().dict)

        if len(result) == 1:
            return result[0]
        else:
            return tuple(result)

    def post(self, url, file=None, data=None, save=None, headers={}, multipart=False, return_url=False, return_headers=False, code=False):
        if not (file or data):
            return self.get(url, save, headers=headers)

        response = None
        result = []

        if multipart:
            data, _headers = multipart_encode(data)
            if not headers:
                headers = _headers
            else:
                headers = headers.copy()
                headers.update(_headers)
        else:
            if type(data) in (list,tuple,set,frozenset):
                data = urllib.urlencode({
                    k:v for k,v in data
                })
            elif type(data) == dict:
                data = urllib.urlencode(data)

        url = urllib2.Request(url, data, headers)

        if file:
            with open(file, 'rb') as body:
                response = self.opener.open(url, body, timeout=self.timeout)
        else:
            response = self.opener.open(url, timeout=self.timeout)

        if save:
            with open(save, 'w+b') as output:
                while True:
                    chunk = response.read(65535)
                    if not chunk:
                        break

                    output.write(chunk)

                result = [save]
        else:
            result = [response.read()]

        if return_url:
            result.append(response.url)

        if code:
            result.append(response.code)

        if return_headers:
            result.append(response.info().dict)

        if len(result) == 1:
            return result[0]
        else:
            return tuple(result)

from network.lib.proxies import find_default_proxy
