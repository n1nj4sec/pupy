# -*- coding: utf-8 -*-

__all__ = ['get_proxies']

import re
import os
import socket
import time

from . import getLogger
logger = getLogger('proxies')

PROXY_MATCHER = re.compile(
    r'^(?:(?P<schema>[a-z45]+)://)?(?:(?P<user>\w+):?(?P<password>\w*)@)?(?P<proxy_addr>\S+:[0-9]+)/*$'
)

PROXY_ENV = [
    'http_proxy', 'https_proxy', 'rsync_proxy', 'all_proxy',
    'rvm_proxy'
]

PROXY_ENV += [
    x.upper() for x in PROXY_ENV
]

LAST_PROXY = None
LAST_PROXY_TIME = None

gio = None

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
            proxies.append((tab[0].upper(), tab[1], None, None)) #type, addr:port, username, password
        else:
            proxies.append(('HTTP', p, None, None))
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
    global PROXY_MATCHER

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

        yield(key.upper(), proxy, user, passwd)

def parse_env_proxies(var):
    global PROXY_MATCHER

    match = PROXY_MATCHER.match(var)
    if not match:
        return

    schema, user, passwd, proxy = match.groups()
    if not schema:
        yield ('HTTP', proxy, user, passwd)
        yield ('SOCKS5', proxy, user, passwd)
        yield ('SOCKS4', proxy, user, passwd)
    elif schema.lower().startswith('http'):
        yield ('HTTP', proxy, user, passwd)
    elif schema.lower() == 'socks4':
        yield ('SOCKS4', proxy, user, passwd)
    elif schema.lower() == 'socks5':
        yield ('SOCKS5', proxy, user, passwd)
    elif schema.lower().startswith('socks'):
        yield ('SOCKS5', proxy, user, passwd)
        yield ('SOCKS4', proxy, user, passwd)

def get_env_proxies():
    global PROXY_ENV

    for env in PROXY_ENV:
        var = os.environ.get(env)
        if not var:
            continue

        for proxy in parse_env_proxies(var):
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
            yield ('HTTP', '{}:{}'.format(host, port), user, password)

        socks = gio.g_settings_get_child(proxy, 'socks')
        host = gio.g_settings_get_string(socks, 'host')
        port = gio.g_settings_get_int(socks, 'port')
        gio.g_object_unref(socks)

        if host and port:
            logger.debug('SOCKS Proxy found via GIO: %s:%s user=%s password=%s', host, port, user, password)
            yield ('SOCKS', '{}:{}'.format(host, port), None, None)

    except Exception, e:
        logger.exception('GIO request exception: %s', e)

    finally:
        gio.g_object_unref(proxy)


def get_processes_proxies():
    global PROXY_ENV

    try:
        import psutil
    except:
        return

    proxies = set()

    for p in psutil.process_iter():
        environ = p.as_dict(['environ'])['environ']
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


LAST_WPAD = None
def get_wpad_proxies(wpad_timeout=600):
    global LAST_WPAD

    # to avoid flooding the network with wpad requests :)
    if LAST_WPAD is None or time.time() - LAST_WPAD > wpad_timeout:
        LAST_WPAD = time.time()
        try:
            wpad_domain = socket.getfqdn('wpad')
            wpad_request = urllib.urlopen('http://%s/wpad.dat'%(wpad_domain))
            wpad_data = wpad_request.read()
            r=re.findall(r'PROXY\s+([a-zA-Z0-9.-]+:[0-9]+);?\s*', wpad_data)
            for p in r:
                logger.debug('HTTP Proxy found via wpad: %s', p)
                yield ('HTTP', p, None, None)

        except:
            pass


def get_proxies(additional_proxies=None):
    global PROXY_MATCHER
    global LAST_PROXY

    dups = set()

    if LAST_PROXY is not None:
        dups.add(LAST_PROXY)
        yield LAST_PROXY

    if additional_proxies is not None:
        for proxy_str in additional_proxies:
            if not proxy_str:
                continue

            login, password = None, None

            if hasattr(proxy_str, 'as_tuple'):
                proxy = proxy_str.as_tuple()
                if proxy not in dups:
                    yield proxy
                    dups.add(proxy)
            # HTTP:login:password@ip:port
            elif '://' in proxy_str:
                for proxy in parse_env_proxies(proxy_str):
                    if proxy not in dups:
                        yield proxy
                        dups.add(proxy)
            else:
                #HTTP:ip:port OR HTTP:ip:[port:]login:password
                parts = proxy_str.split(':')

                if len(parts) >= 4:
                    login, password = parts[-2], parts[-1]
                    parts = parts[:-2]

                if len(parts) not in (2,3):
                    continue

                elif len(parts) == 2:
                    proxy_type = 'SOCKS5'
                    address, port = parts
                else:
                    proxy_type, address, port = parts

                proxy = proxy_type.upper(), address+':'+port, login, password
                if proxy not in dups:
                    yield proxy
                    dups.add(proxy)

    for proxy in get_python_proxies():
        if proxy not in dups:
            yield proxy
            dups.add(proxy)

    for proxy in get_env_proxies():
        if proxy not in dups:
            yield proxy
            dups.add(proxy)

    for proxy in get_wpad_proxies():
        if proxy not in dups:
            yield proxy
            dups.add(proxy)

    if os.name == 'nt':
        for proxy in get_win_proxies():
            if proxy not in dups:
                yield proxy
                dups.add(proxy)

    elif os.name == 'posix':
        for proxy in get_gio_proxies():
            if proxy not in dups:
                yield proxy
                dups.add(proxy)

    for proxy in get_processes_proxies():
        if proxy not in dups:
            yield proxy
            dups.add(proxy)

from network.lib.tinyhttp import HTTP

def find_default_proxy():
    global LAST_PROXY, LAST_PROXY_TIME

    if LAST_PROXY_TIME is not None:
        if time.time() - LAST_PROXY_TIME < 3600:
            logger.debug('Cached default proxy: %s', LAST_PROXY)
            return LAST_PROXY

    logger.debug('Refresh required')

    LAST_PROXY_TIME = time.time()

    for proxy_info in get_proxies():
        logger.debug('%s - check', proxy_info)
        ctx = HTTP(proxy=proxy_info, timeout=5)
        try:
            data, code = ctx.get(
                'http://connectivitycheck.gstatic.com/generate_204',
                code=True)

        except Exception, e:
            logger.debug('%s - failed - %s', proxy_info, e)
            continue

        if code == 204 and data == '':
            LAST_PROXY = proxy_info
            logger.debug('%s - ok', proxy_info)
            break

    return LAST_PROXY
