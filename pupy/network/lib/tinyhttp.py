# -*- coding: utf-8 -*-

__all__ = ('HTTP',)


import urllib2
import urllib
import cookielib
import urlparse
import httplib
import ssl
import socket
import types

import StringIO

from netaddr import IPAddress, AddrFormatError

from .socks import (
    ProxyConnectionError, socksocket, PROXY_TYPES, DEFAULT_PORTS
)

from .socks import HTTP as PROXY_SCHEME_HTTP

from poster.streaminghttp import StreamingHTTPConnection, StreamingHTTPSConnection
from poster.streaminghttp import StreamingHTTPHandler, StreamingHTTPSHandler
from ntlm.HTTPNtlmAuthHandler import ProxyNtlmAuthHandler, HTTPNtlmAuthHandler

try:
    from urllib_kerberos import ProxyKerberosAuthHandler, HTTPKerberosAuthHandler
    KerberosInitError = None

except ImportError:
    import traceback

    ProxyKerberosAuthHandler = None
    HTTPKerberosAuthHandler = None
    KerberosInitError = traceback.format_exc()

from poster.encode import multipart_encode

from .netcreds import (
    find_first_cred, find_creds_for_uri, add_cred_for_uri, add_cred
)

from . import getLogger

logger = getLogger('tinyhttp')

if KerberosInitError is not None:
    logger.warning('Kerberos disabled: %s', KerberosInitError)

def merge_dict(a, b):
    d = a.copy()
    d.update(b)
    return d

## Fix poster bug

class OptionalPasswordManager(object):
    __slots__ = ('username', 'password', 'authuri', 'realm')

    def __init__(self, username=None, password=None):
        self.authuri = None
        self.realm = None
        self.username = username
        self.password = password

    def find_user_password(self, realm, authuri):
        if self.username and self.password:
            self.authuri = authuri
            self.realm = realm
            logger.info(
                'Force preconfigured user/password for %s (realm=%s) -> user=%s',
                authuri, realm, self.username
            )
            return self.username, self.password
        else:
            for cred in find_creds_for_uri(authuri, realm=realm):
                username = cred.username
                if cred.domain:
                    username = cred.domain + '\\' + username

                logger.info(
                    'Found creds for %s (realm=%s) -> user=%s',
                    authuri, realm, username
                )
                return username, cred.password

        logger.info('Creds for %s (realm=%s) not found', authuri, realm)
        return None, None

    def add_password(self, *args, **kwargs):
        raise NotImplementedError('add_password is not implemented')

    def commit(self):
        if self.username and self.password and self.authuri:
            add_cred_for_uri(self.username, self.password, self.authuri, self.realm)


class ProxyPasswordManager(object):
    # Dumb urllib2 doesn't distinguish 401/407, so it's no way to find the proxy address

    __slots__ = ('username', 'password', 'schema', 'host', 'port')

    def __init__(self, schema=None, host=None, port=None, username=None, password=None):
        self.schema = schema
        self.host = host
        self.port = int(port) if port else None
        self.username = username
        self.password = password

    def find_user_password(self, *args, **kwargs):
        if self.username and self.password:
            return self.username, self.password

        elif self.schema and self.host and self.port:
            cred = find_first_cred(self.schema, self.host, self.port)
            if cred:
                return cred.user, cred.password

        return None, None

    def add_password(self, *args, **kwargs):
        raise NotImplementedError('add_password is not implemented')

    def commit(self):
        if all([self.username, self.password, self.schema, self.host, self.port]):
            add_cred(self.username, self.password, True, self.schema, self.host, None, self.port)

class HTTPContext(urllib2.BaseHandler):
    default = None

    __slots__ = ('cookies', 'headers')

    handler_order = 999

    @staticmethod
    def get_default():
        if HTTPContext.default is None:
            HTTPContext.default = HTTPContext()

        return HTTPContext.default

    def __init__(self):
        self.cookies = cookielib.CookieJar()
        self.headers = {}

    def http_request(self, request):
        self.cookies.add_cookie_header(request)
        host = request.get_host()

        if host in self.headers:
            for header, value in self.headers[host].iteritems():
                request.add_header(header, value)

        return request

    def http_response(self, request, response):
        self.cookies.extract_cookies(response, request)

        host = request.get_host()
        headers = request.headers
        code = response.headers

        self._process(host, code, headers)
        return response

    def update_from_error(self, error):
        host = urlparse.urlparse(error.url).hostname
        headers = error.hdrs
        code = error.code

        self._process(host, code, headers)

    def _process(self, host, code, headers):
        for header in ('proxy-authorization', 'authorization'):
            if header in headers:
                if code in (401, 407):
                    if host in self.headers and header in self.headers[host]:
                        del self.headers[host][header]
                        if not self.headers[host]:
                            del self.headers[host]
                else:
                    if host not in self.headers:
                        self.headers[host] = {}

                    self.headers[host][header] = headers.get(header)

    https_request = http_request
    https_response = http_response


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
            self.sock = socksocket()
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
            sock = socksocket()
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

    __slots__ = (
        'ctx', 'proxy', 'noverify',
        'no_proxy_locals', 'no_proxy_for',
        'timeout', 'headers', 'follow_redirects')

    def __init__(
        self,
            proxy=None, noverify=True, follow_redirects=False,
            headers={}, timeout=5, cadata=None,
            no_proxy_locals=True, no_proxy_for=[]):

        self.ctx = ssl.create_default_context(cadata=cadata)

        if noverify:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

        self.proxy = None
        self.headers = headers
        self.follow_redirects = follow_redirects
        self.no_proxy_locals = no_proxy_locals
        self.no_proxy_for = no_proxy_for

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
            if has_wpad():
                self.proxy = 'wpad'
            else:
                self.proxy = find_default_proxy()
        elif hasattr(proxy, 'as_tuple'):
            self.proxy = proxy.as_tuple()
        else:
            self.proxy = proxy

        self.noverify = noverify
        self.timeout = timeout

    def _is_local_network(self, address):
        url = urlparse.urlparse(address)
        try:
            net = IPAddress(url)
            return net.is_private()
        except (AddrFormatError, TypeError):
            return False

    def _is_direct(self, address):
        if self.no_proxy_locals and self._is_local_network(address):
            return True

        if self.no_proxy_for and urlparse.urlparse(
                address).hostname in self.no_proxy_for:
            return True

        return False

    def make_opener(self, address):
        scheme = None
        proxy_host = None
        proxy_password_manager = None
        http_password_manager = OptionalPasswordManager()
        password_managers = []

        if self.proxy == 'wpad':
            proxy = get_proxy_for_address(address)
            if proxy:
                proxy = proxy[0]
            else:
                proxy = None
        else:
            proxy = self.proxy

        if not proxy or proxy[0] == 'DIRECT' or self._is_direct(address):
            handlers = [
                StreamingHTTPHandler,
                StreamingHTTPSHandler(context=self.ctx),
                TCPReaderHandler(context=self.ctx)
            ]
        else:
            scheme, host, user, password = proxy

            scheme = PROXY_TYPES[scheme]
            port = DEFAULT_PORTS[scheme]

            if ':' in host:
                host, maybe_port = host.split(':')

                try:
                    port = int(maybe_port)
                except ValueError:
                    pass

            proxy_host = host+':'+str(port)

            sockshandler = SocksiPyHandler(
                scheme, host, port,
                user or None, password or None,
                context=self.ctx if self.noverify else None
            )

            handlers = []

            if scheme == PROXY_SCHEME_HTTP:
                http_proxy = proxy_host

                handlers.append(urllib2.ProxyHandler({
                    'http': 'http://' + http_proxy
                }))

                proxy_password_manager = ProxyPasswordManager(
                    'http', host, port, user, password
                )

                for handler_klass in (
                    ProxyKerberosAuthHandler, ProxyNtlmAuthHandler,
                        urllib2.ProxyBasicAuthHandler, urllib2.ProxyDigestAuthHandler):
                    if handler_klass is None:
                        continue

                    instance = handler_klass(proxy_password_manager)
                    if hasattr(instance, 'set_logger'):
                        instance.set_logger(logger)

                    handlers.append(instance)

                password_managers.append(proxy_password_manager)
                handlers.append(StreamingHTTPHandler)

            handlers.append(sockshandler)

        if self.follow_redirects:
            handlers.append(urllib2.HTTPRedirectHandler)
        else:
            handlers.append(NoRedirects)

        handlers.append(UDPReaderHandler)

        for handler_klass in (
            urllib2.HTTPBasicAuthHandler, urllib2.HTTPDigestAuthHandler,
                ProxyKerberosAuthHandler, HTTPNtlmAuthHandler):

            if handler_klass is None:
                continue

            instance = handler_klass(http_password_manager)
            if hasattr(instance, 'set_logger'):
                instance.set_logger(logger)

            handlers.append(instance)

        password_managers.append(http_password_manager)

        context = HTTPContext.get_default()

        handlers.append(context)

        handlers.append(urllib2.HTTPDefaultErrorHandler)
        handlers.append(urllib2.HTTPErrorProcessor)

        opener = urllib2.OpenerDirector()
        for h in handlers:
            if isinstance(h, (types.ClassType, type)):
                h = h()

            opener.add_handler(h)

        if type(self.headers) == dict:
            opener.addheaders = [
                (x, y) for x,y in self.headers.iteritems()
            ]
        else:
            opener.addheaders = self.headers

        return opener, scheme, proxy_host, password_managers, context

    def get(
            self, url, save=None, headers=None, return_url=False,
            return_headers=False, code=False, params={}):

        if params:
            url = url + '?' + urllib.urlencode(params)

        if headers:
            url = urllib2.Request(url, headers=headers)

        opener, scheme, host, password_managers, context = self.make_opener(url)

        result = []

        try:
            response = opener.open(url, timeout=self.timeout)

        except ProxyConnectionError as e:
            if self.proxy == 'wpad':
                set_proxy_unavailable(scheme, host)

            raise e

        except urllib2.HTTPError as e:
            context.update_from_error(e)

            result = [e.fp.read() if e.fp.read else '']

            if return_url:
                result.append(e.url)

            if code:
                result.append(e.code)

            if return_headers:
                result.append(e.hdrs.dict)

            if len(result) == 1:
                return result[0]
            else:
                return tuple(result)

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

        if response.code not in (401, 407) and password_managers:
            for password_manager in password_managers:
                password_manager.commit()

        if len(result) == 1:
            return result[0]
        else:
            return tuple(result)

    def post(
            self, url, file=None, data=None, save=None, headers={},
            multipart=False, return_url=False, return_headers=False,
            code=False, params={}):

        if not (file or data):
            return self.get(url, save, headers2=headers)

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

        if params:
            url = url + '?' + urllib.urlencode(params)

        url = urllib2.Request(url, data, headers)

        opener, scheme, host, password_managers, context = self.make_opener(url)

        try:
            if file:
                with open(file, 'rb') as body:
                    response = opener.open(url, body, timeout=self.timeout)
            else:
                response = opener.open(url, timeout=self.timeout)

        except ProxyConnectionError as e:
            if self.proxy == 'wpad':
                set_proxy_unavailable(scheme, host)

            raise e

        except urllib2.HTTPError as e:
            result = [e.fp.read() if e.fp.read else '']

            if return_url:
                result.append(e.url)

            if code:
                result.append(e.code)

            if return_headers:
                result.append(e.hdrs.dict)

            if len(result) == 1:
                return result[0]
            else:
                return tuple(result)

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

        if response.code not in (401, 407) and password_managers:
            for password_manager in password_managers:
                password_manager.commit()

        if len(result) == 1:
            return result[0]
        else:
            return tuple(result)

from .proxies import (
    find_default_proxy, set_proxy_unavailable,
    has_wpad, get_proxy_for_address
)
