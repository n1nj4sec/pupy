# -*- coding: utf-8 -*-

__all__ = [ 'HTTP' ]

import urllib2
import urllib
import urlparse
import httplib
import base64
import ssl

from poster.streaminghttp import StreamingHTTPConnection, StreamingHTTPSConnection
from poster.streaminghttp import StreamingHTTPHandler, StreamingHTTPSHandler
from poster.encode import multipart_encode

from . import socks

def merge_dict(a, b):
    d = a.copy()
    d.update(b)
    return d

## Fix poster bug

class NoRedirects(urllib2.HTTPErrorProcessor):

    def http_response(self, request, response):
        return response

    https_response = http_response

class NullConnection(httplib.HTTPConnection):
    def __init__(self, socket, timeout, *args, **kwargs):
        httplib.HTTPConnection.__init__(self, *args, **kwargs)
        self.sock = socket
        self.timeout = timeout

    def connect(self):
        self.sock.settimeout(self.timeout)

class NullHandler(urllib2.HTTPHandler):
    def __init__(self, table, lock):
        urllib2.HTTPHandler.__init__(self)
        self.table = table
        self.lock = lock

    def http_open(self, req):
        def build(host, port=None, strict=None, timeout=0):
            with self.lock:
                return NullConnection(self.table[host], timeout, host)

        return self.do_open(build, req)

StreamingHTTPSHandler.https_open = lambda self, req: self.do_open(
    StreamingHTTPSConnection, req, context=self._context)

class SocksiPyConnection(StreamingHTTPConnection):
    def __init__(self, proxytype, proxyaddr, proxyport=None, rdns=True, username=None, password=None, *args, **kwargs):
        self.proxyargs = (proxytype, proxyaddr, proxyport, rdns, username, password)
        httplib.HTTPConnection.__init__(self, *args, **kwargs)

    def connect(self):
        self.sock = socks.socksocket()
        self.sock.setproxy(*self.proxyargs)
        if isinstance(self.timeout, float):
            self.sock.settimeout(self.timeout)
        self.sock.connect((self.host, self.port))

class SocksiPyConnectionS(StreamingHTTPSConnection):
    def __init__(self, proxytype, proxyaddr, proxyport=None, rdns=True, username=None, password=None, *args, **kwargs):
        self.proxyargs = (proxytype, proxyaddr, proxyport, rdns, username, password)
        httplib.HTTPSConnection.__init__(self, *args, **kwargs)

    def connect(self):
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

class SocksiPyHandler(urllib2.HTTPHandler, urllib2.HTTPSHandler):
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kw = kwargs
        urllib2.HTTPHandler.__init__(self)

    def http_open(self, req):
        def build(host, port=None, strict=None, timeout=0):
            if 'context' in self.kw:
                kw = {
                    x:y for x,y in self.kw.iteritems() if not x in ('context')
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

class HTTP(object):
    def __init__(self, proxy=None, noverify=True, follow_redirects=False, headers={}, timeout=5, cadata=None):
        self.ctx = ssl.create_default_context()

        if noverify:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

        if cadata:
            self.ctx.load_verify_locations(None, None, cadata)

        self.proxy = proxy
        self.noverify = noverify
        self.timeout=timeout

        handlers = []

        if self.proxy is None or self.proxy is True:
            handlers = [
                urllib2.ProxyHandler(),
                StreamingHTTPHandler,
                StreamingHTTPSHandler(context=self.ctx)
            ]

        elif self.proxy is False:
            handlers = [
                StreamingHTTPHandler,
                StreamingHTTPSHandler(context=self.ctx)
            ]
        else:
            proxyscheme = urlparse.urlparse(self.proxy)
            scheme = proxyscheme.scheme.upper()
            if scheme == 'SOCKS':
                scheme = 'SOCKS5'

            scheme = socks.PROXY_TYPES[scheme]
            sockshandler = SocksiPyHandler(
                scheme,
                proxyscheme.hostname,
                proxyscheme.port or socks.DEFAULT_PORTS[scheme],
                username=proxyscheme.username or None,
                password=proxyscheme.password or None,
                context=self.ctx if self.noverify else None
            )

            handlers = [ sockshandler ]

        if not follow_redirects:
            handlers.append(NoRedirects)

        self.opener = urllib2.build_opener(*handlers)

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
        if not ( file or data ):
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
            with open(file, 'rb') as input:
                response = self.opener.open(url, timeout=self.timeout)
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
