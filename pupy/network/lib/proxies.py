# -*- coding: utf-8 -*-

__all__ = [ 'get_proxies' ]

import re
import os
import socket
import time

PROXY_MATCHER = re.compile(
    '^(?:(?P<schema>[a-z45]+)://)?(?:(?P<user>\w+):?(?P<password>\w*)@)?(?P<proxy_addr>\S+:[0-9]+)/*$'
)

PROXY_ENV = [
    'http_proxy', 'https_proxy', 'rsync_proxy', 'all_proxy',
    'rvm_proxy'
]

PROXY_ENV += [
    x.upper() for x in PROXY_ENV
]

try:
    from urllib import request as urllib
except ImportError:
    import urllib2 as urllib

def parse_win_proxy(val):
    l=[]
    for p in val.split(';'):
        if '=' in p:
            tab=p.split('=',1)
            if tab[0]=='socks':
                tab[0]='SOCKS4'
            l.append((tab[0].upper(), tab[1], None, None)) #type, addr:port, username, password
        else:
            l.append(('HTTP', p, None, None))
    return l

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

        yield(key.upper(), proxy, user, passwd)

def parse_env_proxies(var):
    global PROXY_MATCHER

    schema, user, passwd, proxy = PROXY_MATCHER.match(var).groups()
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


def get_gio_proxies(force=True):
    import ctypes
    try:
        gio = ctypes.CDLL('libgio-2.0.so')

        schema = 'org.gnome.system.proxy'
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

        gio.g_settings_schema_source_get_default.restype = ctypes.c_void_p

        gio.g_settings_schema_source_lookup.restype = ctypes.c_void_p
        gio.g_settings_schema_source_lookup.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_bool
        ]

        gio.g_settings_schema_source_unref.argtypes = [ctypes.c_void_p]

    except:
        return

    sources = gio.g_settings_schema_source_get_default()
    proxy_schema = gio.g_settings_schema_source_lookup(sources, schema, True)
    schema_found = bool(proxy_schema)
    gio.g_settings_schema_source_unref(sources)

    if not schema_found:
        return

    try:
        proxy = gio.g_settings_new(schema)

        mode = gio.g_settings_get_string(proxy, 'mode')
        if not force and ( not mode or mode == 'none' ):
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
            yield ('HTTP', '{}:{}'.format(host, port), user, password)

        socks = gio.g_settings_get_child(proxy, 'socks')
        host = gio.g_settings_get_string(socks, 'host')
        port = gio.g_settings_get_int(socks, 'port')
        gio.g_object_unref(socks)

        if host and port:
            yield ('SOCKS', '{}:{}'.format(host, port), None, None)

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
            if not var in environ or not environ[var]:
                continue

            proxies.add(environ[var])

    for proxy in proxies:
        for parsed in parse_env_proxies(proxy):
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
                yield ('HTTP', p, None, None)

        except:
            pass


def get_proxies(additional_proxies=None):
    global PROXY_MATCHER

    dups = set()

    if additional_proxies != None:
        for proxy_str in additional_proxies:
            if not proxy_str:
                continue

            login, password = None, None

            # HTTP:login:password@ip:port
            if '://' in proxy_str:
                for proxy in parse_env_proxies(proxy_str):
                    if not proxy in dups:
                        yield proxy
                        dups.add(proxy)
            else:
                if '@' in proxy_str:
                    tab=proxy_str.split(':',1)
                    proxy_type=tab[0]
                    login, password=(tab[1].split('@')[0]).split(':',1)
                    address, port = tab[1].split('@')[1].split(':',1)
                else:
                    #HTTP:ip:port
                    parts = proxy_str.split(':')
                    if len(parts) not in (2,3):
                        continue
                    elif len(parts) == 2:
                        proxy_type = 'SOCKS5'
                        address, port = parts
                    else:
                        proxy_type, address, port = parts

                proxy = proxy_type.upper(), address+':'+port, login, password
                if not proxy in dups:
                    yield proxy
                    dups.add(proxy)

    for proxy in get_python_proxies():
        if not proxy in dups:
            yield proxy
            dups.add(proxy)

    for proxy in get_env_proxies():
        if not proxy in dups:
            yield proxy
            dups.add(proxy)

    for proxy in get_wpad_proxies():
        if not proxy in dups:
            yield proxy
            dups.add(proxy)

    if os.name == 'nt':
        for proxy in get_win_proxies():
            if not proxy in dups:
                yield proxy
                dups.add(proxy)

    elif os.name == 'posix':
        for proxy in get_gio_proxies():
            if not proxy in dups:
                yield proxy
                dups.add(proxy)

    for proxy in get_processes_proxies():
        if not proxy in dups:
            yield proxy
            dups.add(proxy)
