# -*- coding: utf-8 -*-
import tinyhttp
import socket
import time
import threading
import random
import httplib
import urllib2
import scan
import netaddr
import struct
import igd

ONLINE_CAPTIVE = 1 << 0
ONLINE_MS      = 1 << 1
ONLINE         = ONLINE_MS | ONLINE_CAPTIVE
HOTSPOT        = 1 << 2
DNS			   = 1 << 3
DIRECT_DNS     = 1 << 4
HTTP		   = 1 << 5
HTTPS		   = 1 << 6
HTTPS_NOCERT   = 1 << 7
HTTPS_MITM	   = 1 << 8
PROXY		   = 1 << 9
TRANSPARENT	   = 1 << 10
IGD            = 1 << 11

PASTEBIN       = 1 << 12
HASTEBIN       = 1 << 13
IXIO           = 1 << 14
DPASTE         = 1 << 15
VPASTE         = 1 << 16
PASTEOPENSTACK = 1 << 17
GHOSTBIN       = 1 << 18
PHPASTE        = 1 << 19
FRIENDPASTE    = 1 << 20
LPASTE         = 1 << 21


# Don't want to import large (200k - 1Mb) dnslib/python dns just for that..
OPENDNS_REQUEST = '\xe4\x9a\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04' \
                  'myip\x07opendns\x03com\x00\x00\x01\x00\x01'
OPENDNS_RESPONSE = '\xe4\x9a\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x04' \
                   'myip\x07opendns\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00' \
                   '\x01\x00\x01\x00\x00\x00\x00\x00\x04'

PASTEBINS = {
    'https://pastebin.com': PASTEBIN,
    'https://hastebin.com': HASTEBIN,
    'http://ix.io': IXIO,
    'http://dpaste.com': DPASTE,
    'http://vpaste.net': VPASTE,
    'http://lpaste.net': LPASTE,
    'http://paste.openstack.org': PASTEOPENSTACK,
    'https://ghostbin.com': GHOSTBIN,
    'https://phpaste.sourceforge.io': PHPASTE,
    'https://friendpaste.com': FRIENDPASTE
}

CHECKS = {
    'msonline': {
        'url': 'http://www.msftncsi.com/ncsi.txt',
        'text': 'Microsoft NCSI',
    },

    'http': {
        'url': 'http://www.boost.org/LICENSE_1_0.txt',
        'text': 'Permission is hereby granted, free of charge, to any person or organization',
    },
    'https': {
        'url': 'https://www.openssl.org/source/license.txt',
        'text': 'Redistributions in binary form must reproduce the above copyright',
        'ca':
        		'MIIDSjCCAjKgAwIBAgIQRK+wgNajJ7qJMDmGLvhAazANBgkqhkiG9w0BAQUFADA/'
                'MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT'
                'DkRTVCBSb290IENBIFgzMB4XDTAwMDkzMDIxMTIxOVoXDTIxMDkzMDE0MDExNVow'
                'PzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1cmUgVHJ1c3QgQ28uMRcwFQYDVQQD'
                'Ew5EU1QgUm9vdCBDQSBYMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB'
                'AN+v6ZdQCINXtMxiZfaQguzH0yxrMMpb7NnDfcdAwRgUi+DoM3ZJKuM/IUmTrE4O'
                'rz5Iy2Xu/NMhD2XSKtkyj4zl93ewEnu1lcCJo6m67XMuegwGMoOifooUMM0RoOEq'
                'OLl5CjH9UL2AZd+3UWODyOKIYepLYYHsUmu5ouJLGiifSKOeDNoJjj4XLh7dIN9b'
                'xiqKqy69cK3FCxolkHRyxXtqqzTWMIn/5WgTe1QLyNau7Fqckh49ZLOMxt+/yUFw'
                '7BZy1SbsOFU5Q9D8/RhcQPGX69Wam40dutolucbY38EVAjqr2m7xPi71XAicPNaD'
                'aeQQmxkqtilX4+U9m5/wAl0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNV'
                'HQ8BAf8EBAMCAQYwHQYDVR0OBBYEFMSnsaR7LHH62+FLkHX/xBVghYkQMA0GCSqG'
                'SIb3DQEBBQUAA4IBAQCjGiybFwBcqR7uKGY3Or+Dxz9LwwmglSBd49lZRNI+DT69'
                'ikugdB/OEIKcdBodfpga3csTS7MgROSR6cz8faXbauX+5v3gTt23ADq1cEmv8uXr'
                'AvHRAosZy5Q6XkjEGB5YGV8eAlrwDPGxrancWYaLbumR9YbK+rlmM6pZW87ipxZz'
                'R8srzJmwN0jP41ZL9c8PDHIyh8bwRLtTcm1D9SZImlJnt1ir/md2cXjbDaJWFBM5'
                'JDGFoqgCWjBH4d1QB7wCCZAA62RjYJsWvIjJEubSfZGL+T0yjWW06XyxV3bqxbYo'
                'Ob8VZRzI9neWagqNdwvYkQsEjgfbKbYK7p2CNTUQ'
    },
}

CAPTIVE_URLS = [
    'http://connectivitycheck.gstatic.com/generate_204',
    'http://clients3.google.com/generate_204',
]

KNOWN_DNS = {
    'opendns.org': '67.215.92.210',
    'quad9.net': '216.21.3.77',
}


IP_KNOWN_TO_BE_DOWN='1.2.3.4'

OWN_IP = [
    'http://ifconfig.co',
    'http://ifconfig.me/ip',
    'http://eth0.me',
    'http://ipecho.net/plain',
    'http://icanhazip.com',
    'http://curlmyip.com',
    'http://l2.io/ip'
    'http://ip.appspot.com'
]

def check_transparent_proxy():
    try:
        s = socket.create_connection((IP_KNOWN_TO_BE_DOWN, 80), timeout=5)
        s.settimeout(5)
        s.send('GET / HTTP/3.0\r\n\r\n')
        data = s.recv(12)
        if data.startswith('HTTP'):
            return True
    except:
        pass

    return False

def external_ip():
    ctx = tinyhttp.HTTP(timeout=15, headers={'User-Agent': 'curl/7.12.3'})
    for service in OWN_IP:
        try:
            data, code = ctx.get(service, code=True)
            if code == 200:
                return netaddr.IPAddress(data.strip())
        except:
            pass

    return dns_external_ip()

def dns_external_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    try:
        s.settimeout(5)
        s.sendto(OPENDNS_REQUEST, ('resolver1.opendns.com', 53))
        data = s.recv(256)
        if data.startswith(OPENDNS_RESPONSE):
            return netaddr.IPAddress(struct.unpack('>I', data[-4:])[0])
    except:
        pass

    return None

def external_headers():
    ctx = tinyhttp.HTTP(timeout=15, headers={'User-Agent': 'curl/7.12.3'})
    try:
        import json
        return json.loads(ctx.get('http://httpbin.org/headers'))['headers']
    except:
        return None

def online():
    headers = {
        'User-Agent': 'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; Trident/6.0)'
    }
    ctx = tinyhttp.HTTP(timeout=5, headers=headers)

    try:
        data = ctx.get(CHECKS['msonline']['url'])
        if data == CHECKS['msonline']['text']:
            return True
    except:
        pass

    return False


def check():
    headers = {
        'User-Agent': 'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; Trident/6.0)'
    }
    ctx = tinyhttp.HTTP(proxy=True, noverify=False, timeout=15, headers=headers)
    ctx_nocert = tinyhttp.HTTP(proxy=True, timeout=15, noverify=True, headers=headers)
    ctx_noproxy = tinyhttp.HTTP(proxy=False, noverify=False, timeout=15, headers=headers)
    ctx_mitm = tinyhttp.HTTP(
        proxy=True, noverify=False, timeout=15,
        cadata=CHECKS['https']['ca'].decode('base64'), headers=headers)

    result = 0

    mintime = None
    need_proxy = False
    ok = 0

    now = time.time()

    for url in CAPTIVE_URLS:
        try:
            data, code = ctx.get(url, code=True)
            t = time.time()
            if mintime is None or mintime > t - now:
                mintime = t - now

            now = t

            if data == '' and code == 204:
                ok += 1

            if code == 302:
                result |= HOTSPOT

        except Exception, e:
            pass

    if ok == 2:
        result |= ONLINE_CAPTIVE

    try:
        data = ctx.get(CHECKS['msonline']['url'])
        t = time.time()
        if mintime is None or mintime > t - now:
            mintime = t - now

        now = t

        if data == CHECKS['msonline']['text']:
            result |= ONLINE_MS

    except Exception, e:
        pass

    for url in CAPTIVE_URLS:
        try:
            data, code = ctx_noproxy.get(url, code=True)
            if not (data == '' and code == 204) and ok:
                result |= NEED_PROXY
                break

        except:
            pass

    try:
        data = ctx.get(CHECKS['http']['url'])
        if CHECKS['http']['text'] in data:
            result |= HTTP
    except:
        pass

    try:
        data = ctx.get(CHECKS['https']['url'])
        if CHECKS['https']['text'] in data:
            result |= HTTPS
    except:
        pass

    if result & HTTPS:
        try:
            data = ctx_mitm.get(CHECKS['https']['url'])
            if not CHECKS['https']['text'] in data:
                result |= HTTPS_MITM
        except Exception, e:
            result |= HTTPS_MITM

    else:
        try:
            data = ctx_nocert.get(CHECKS['https']['url'])
            if CHECKS['https']['text'] in data:
                result |= HTTPS_NOCERT & HTTPS
        except Exception, e:
            pass

    for hostname, ip in KNOWN_DNS.iteritems():
        try:
            if ip == socket.gethostbyname(hostname):
                result |= DNS
        except Exception, e:
            pass

    for pastebin, bit in PASTEBINS.iteritems():
        try:
            data, code = ctx.get(
                pastebin,
                code=True, headers={'User-Agent': 'curl'}
            )
            if code == 200:
                result |= bit
        except:
            pass

    if check_transparent_proxy():
        result |= TRANSPARENT | PROXY
    else:
        headers = external_headers()
        for header in headers:
            if 'via' in header.lower():
                result |= PROXY
                break

    deip = dns_external_ip()
    if deip:
        result |= DIRECT_DNS

    igdc = igd.IGDClient()
    if igdc.available:
        result |= IGD

    mintime = int(mintime * 100)
    if mintime > 0xFFF:
        mintime = 0xFFF

    result |= mintime << 20
    return result

def bits_to_dict(data):
    return {
        'online': bool(data & ONLINE),
        'online-by': {
            'android': bool(data & ONLINE_CAPTIVE),
            'microsoft': bool(data & ONLINE_MS),
        },
        'igd': bool(data & IGD),
        'hotspot': bool(data & HOTSPOT),
        'dns': bool(data & DNS),
        'direct-dns': bool(data & DIRECT_DNS),
        'http': bool(data & HTTP),
        'https': bool(data & HTTPS),
        'https-no-cert': bool(data & HTTPS_NOCERT),
        'https-mitm': bool(data & HTTPS_MITM),
        'proxy': bool(data & PROXY),
        'transparent-proxy': bool(data & TRANSPARENT),
        'pastebins': {
            pastebin:bool(data & bit) for pastebin,bit in PASTEBINS.iteritems()
        }
    }

class PortQuiz(threading.Thread):

    PORTQUIZ_ADDR='178.33.250.62'
    PORTQUIZ_443_MESSAGE='Your browser sent a request that this server could not understand'
    PORTQUIZ_MESSAGE='<html><body><h1>It works!</h1></body></html>'

    def __init__(self, amount=5, http_timeout=15, connect_timeout=10):
        threading.Thread.__init__(self)
        self.daemon = True

        self.table = {}
        self.lock = threading.Lock()
        self.abort = threading.Event()
        self.amount = 8
        self.opener = urllib2.build_opener(tinyhttp.NullHandler(self.table, self.lock))
        self.http_timeout = http_timeout
        self.connect_timeout = connect_timeout
        self.available = list()

    def _on_open_port(self, info):
        host, port, sock = info

        with self.lock:
            self.table['{}:{}'.format(host,port)] = sock
            sock.setblocking(1)

        try:
            response = self.opener.open('http://{}:{}'.format(host, port), timeout=self.http_timeout)
            data = response.read()
            if data.startswith(self.PORTQUIZ_MESSAGE) or port == 443 and self.PORTQUIZ_443_MESSAGE in data:
                self.available.append(port)
                if len(self.available) >= self.amount:
                    self.abort.set()

        except Exception, e:
            pass

        finally:
            try:
                sock.close()
            except:
                pass

    def run(self):
        most_important = [ 80, 443, 8080, 53, 5222, 25, 110, 465 ]

        r = scan.scan([self.PORTQUIZ_ADDR], most_important, timeout=self.connect_timeout, abort=self.abort,
             on_open_port=self._on_open_port, pass_socket=True)

        if len(self.available) < self.amount:
             other = list([ x for x in scan.TOP1000 if not x in most_important ])
             random.shuffle(other)

             scan.scan([self.PORTQUIZ_ADDR],other, timeout=self.connect_timeout, abort=self.abort,
                 on_open_port=self._on_open_port, pass_socket=True)
