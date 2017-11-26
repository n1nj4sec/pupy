# -*- coding: utf-8 -*-
import urllib2
import urllib
import urlparse
import httplib
import base64

from network.lib import socks

class SocksiPyConnection(httplib.HTTPConnection):
    def __init__(self, proxytype, proxyaddr, proxyport=None, rdns=True, username=None, password=None, *args, **kwargs):
        self.proxyargs = (proxytype, proxyaddr, proxyport, rdns, username, password)
        httplib.HTTPConnection.__init__(self, *args, **kwargs)

    def connect(self):
        self.sock = socks.socksocket()
        self.sock.setproxy(*self.proxyargs)
        if isinstance(self.timeout, float):
            self.sock.settimeout(self.timeout)
        self.sock.connect((self.host, self.port))

class SocksiPyHandler(urllib2.HTTPHandler):
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kw = kwargs
        urllib2.HTTPHandler.__init__(self)

    def http_open(self, req):
        def build(host, port=None, strict=None, timeout=0):
            conn = SocksiPyConnection(*self.args, host=host, port=port, strict=strict, timeout=timeout, **self.kw)
            return conn
        return self.do_open(build, req)

class HTTP(object):
    def __init__(self, proxy=None, headers={}):
        if proxy is True:
            opener = urllib2.build_opener(urllib2.ProxyHandler())
        elif proxy is None:
            opener = urllib2.build_opener()
        else:
            proxyscheme = urlparse.urlparse(proxy)
            scheme = proxyscheme.scheme.upper()
            if scheme == 'SOCKS':
                scheme = 'SOCKS5'

            scheme = socks.PROXY_TYPES[scheme]

            opener = urllib2.build_opener(
                SocksiPyHandler(
                    scheme,
                    proxyscheme.hostname,
                    proxyscheme.port or socks.DEFAULT_PORTS[scheme],
                    username=proxyscheme.username or None,
                    password=proxyscheme.password or None
                )
            )

        self.opener = opener
        
        if type(headers) == dict:
            self.opener.addheaders = [
                (k, v) for k,v in headers.iteritems()
            ]
        else:
            self.opener.addheaders = headers

    def get(self, url, save=None):
        response = self.opener.open(url)
        if save:
            with open(save, 'w+b') as output:
                while True:
                    chunk = response.read(65535)
                    if not chunk:
                        break

                    output.write(chunk)

            return save
        else:
            return response.read()

    def post(self, url, file=None, data=None, save=None):
        if not ( file or data ):
            return self.get(url, save)

        response = None

        if file:
            with open(file, 'rb') as input:
                response = self.opener.open(url, input)
        else:
            if type(data) not in (str, unicode):
                if not type(data) == dict:
                    data = {
                        k:v for k,v in data
                    }
                    
                data = urllib.urlencode(data)

            response = self.opener.open(url, data)

        if save:
            with open(save, 'w+b') as output:
                while True:
                    chunk = response.read(65535)
                    if not chunk:
                        break

                    output.write(chunk)

                return save

        else:
            return response.read()
