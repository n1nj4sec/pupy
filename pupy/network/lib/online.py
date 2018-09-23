# -*- coding: utf-8 -*-

__all__ = (
    'check_transparent_proxy',
    'external_ip',
    'external_headers',
    'online',
    'ntp_time_diff',
    'check',
    'bits_to_dict',
    'PortQuiz',
)

import tinyhttp
import socket
import time
import threading
import random
import urllib2
import scan
import netaddr
import struct
import igd
import sys
import json

from network.lib import getLogger
logger = getLogger('online')

from . import stun
from . import ntplib

ONLINE_STATUS = None
ONLINE_STATUS_CHECKED = None

ONLINE_CAPTIVE      = 1 << 0
ONLINE_MS           = 1 << 1
ONLINE              = ONLINE_MS | ONLINE_CAPTIVE
HOTSPOT             = 1 << 2
DNS                 = 1 << 3
DIRECT_DNS          = 1 << 4
HTTP                = 1 << 5
HTTPS               = 1 << 6
HTTPS_NOCERT        = 1 << 7
HTTPS_MITM          = 1 << 8
PROXY               = 1 << 9
TRANSPARENT         = 1 << 10
IGD                 = 1 << 11

PASTEBIN            = 1 << 12
HASTEBIN            = 1 << 13
IXIO                = 1 << 14
DPASTE              = 1 << 15
VPASTE              = 1 << 16
PASTEOPENSTACK      = 1 << 17
GHOSTBIN            = 1 << 18
PHPASTE             = 1 << 19
FRIENDPASTE         = 1 << 20
LPASTE              = 1 << 21

STUN_NAT_VALUE      = 7 << 22
STUN_NAT_BLOCKED    = 0 << 22
STUN_NAT_OPEN       = 1 << 22
STUN_NAT_CLONE      = 2 << 22
STUN_NAT_UDP_FW     = 3 << 22
STUN_NAT_RESTRICT   = 4 << 22
STUN_NAT_PORT       = 5 << 22
STUN_NAT_SYMMETRIC  = 6 << 22
STUN_NAT_ERROR      = 7 << 22

NTP                 = 1 << 25

STUN_NAT_DESCRIPTION = {
    STUN_NAT_BLOCKED:   stun.Blocked,
    STUN_NAT_OPEN:      stun.OpenInternet,
    STUN_NAT_CLONE:     stun.FullCone,
    STUN_NAT_UDP_FW:    stun.SymmetricUDPFirewall,
    STUN_NAT_RESTRICT:  stun.RestricNAT,
    STUN_NAT_PORT:      stun.RestricPortNAT,
    STUN_NAT_SYMMETRIC: stun.SymmetricNAT,
    STUN_NAT_ERROR:     stun.ChangedAddressError,
}

NTP_SERVER     = 'pool.ntp.org'

STUN_HOST      = 'stun.l.google.com'
STUN_PORT      = 19302

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
        'url': 'http://lame.sourceforge.net/license.txt',
        'text': 'Can I use LAME in my commercial program?',
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
    'ifconfig.co',
    'ifconfig.me/ip',
    'eth0.me',
    'ipecho.net/plain',
    'icanhazip.com',
    'curlmyip.com',
    'l2.io/ip'
]

LAST_EXTERNAL_IP = None
LAST_EXTERNAL_IP_TIME = None

def check_transparent_proxy():
    logger.debug('Check for transparent proxy')

    try:
        s = socket.create_connection((IP_KNOWN_TO_BE_DOWN, 80), timeout=5)
        s.settimeout(5)
        s.send('GET / HTTP/3.0\r\n\r\n')
        data = s.recv(12)
        if data.startswith('HTTP'):
            return True

    except Exception, e:
        logger.debug('Check transparent proxy: %s', e)

    return False

def external_ip(force_ipv4=False):
    global LAST_EXTERNAL_IP, LAST_EXTERNAL_IP_TIME

    if LAST_EXTERNAL_IP_TIME is not None:
        if time.time() - LAST_EXTERNAL_IP_TIME < 3600:
            logger.debug('Return cached IP (last ts=%d): %d',
                LAST_EXTERNAL_IP_TIME, LAST_EXTERNAL_IP)
            return LAST_EXTERNAL_IP

    logger.debug('Retrieve IP using external services')

    try:
        stun_ip = stun.get_ip(stun_host=STUN_HOST, stun_port=STUN_PORT)
        if stun_ip is not None:
            stun_ip = netaddr.IPAddress(stun_ip)

            LAST_EXTERNAL_IP = stun_ip
            LAST_EXTERNAL_IP_TIME = time.time()

            return LAST_EXTERNAL_IP

    except Exception, e:
        logger.debug('external_ip: STUN failed: %s', e)

    ctx = tinyhttp.HTTP(timeout=15, headers={'User-Agent': 'curl/7.12.3'})
    for service in OWN_IP:
        for scheme in ['https', 'http']:
            try:
                data, code = ctx.get(scheme + '://' + service, code=True)
                if code == 200:
                    addr = netaddr.IPAddress(data.strip())
                    if force_ipv4 and addr.version == 6:
                        continue

                    LAST_EXTERNAL_IP = addr
                    LAST_EXTERNAL_IP_TIME = time.time()

                    return LAST_EXTERNAL_IP

            except Exception, e:
                logger.debug('Get IP service failed: %s: %s', service, e)

    LAST_EXTERNAL_IP = dns_external_ip()
    if LAST_EXTERNAL_IP:
        LAST_EXTERNAL_IP_TIME = time.time()

    return LAST_EXTERNAL_IP

def dns_external_ip():
    logger.debug('Retrieve IP using DNS')

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    try:
        s.settimeout(5)
        s.sendto(OPENDNS_REQUEST, ('resolver1.opendns.com', 53))
        data = s.recv(256)
        if data.startswith(OPENDNS_RESPONSE):
            return netaddr.IPAddress(struct.unpack('>I', data[-4:])[0])

    except Exception, e:
        logger.debug('DNS External IP failed: %s', e)

    return None

def external_headers():
    logger.debug('Retrieve external headers')

    try:
        ctx = tinyhttp.HTTP(timeout=15, headers={'User-Agent': 'curl/7.12.3'})

        data = ctx.get('http://httpbin.org/headers')
        data = json.loads(data)
        return data['headers']

    except Exception, e:
        logger.debug('External headers failed: %s', e)

    return {}

def online():
    headers = {
        'User-Agent': 'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; Trident/6.0)'
    }
    ctx = tinyhttp.HTTP(timeout=5, headers=headers)

    try:
        data = ctx.get(CHECKS['msonline']['url'])
        if data == CHECKS['msonline']['text']:
            return True

    except Exception, e:
        logger.debug('MS Online check failed: %s', e)

    return False

def ntp_time_diff():
    client = ntplib.NTPClient()
    response = client.request(NTP_SERVER, version=3)
    return int(response.offset * 1000000)

def check():
    global ONLINE_STATUS_CHECKED
    global ONLINE_STATUS

    if ONLINE_STATUS_CHECKED is not None:
        if time.time() - ONLINE_STATUS_CHECKED < 3600:
            return ONLINE_STATUS

    logger.debug('Online check started')

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
    offset = 0
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
            logger.debug('Captive check failed %s: %s', url, e)

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
        logger.debug('MS Online check failed: %s', e)

    if result & ONLINE_CAPTIVE:
        for url in CAPTIVE_URLS:
            try:
                data, code = ctx_noproxy.get(url, code=True)
                if not (data == '' and code == 204) and ok:
                    result |= PROXY
                    break

            except Exception, e:
                result |= PROXY
                logger.debug('Captive check failed %s: %s', url, e)

    try:
        data = ctx.get(CHECKS['http']['url'])
        if CHECKS['http']['text'] in data:
            result |= HTTP

    except Exception, e:
        logger.debug('HTTP Check failed: %s', e)

    try:
        data = ctx.get(CHECKS['https']['url'])
        if CHECKS['https']['text'] in data:
            result |= HTTPS

    except Exception, e:
        logger.debug('HTTPS Check failed: %s', e)

    if result & HTTPS:
        try:
            data = ctx_mitm.get(CHECKS['https']['url'])
            if not CHECKS['https']['text'] in data:
                result |= HTTPS_MITM

        except Exception, e:
            logger.debug('HTTPS Mitm Check failed: %s', e)
            result |= HTTPS_MITM

    else:
        try:
            data = ctx_nocert.get(CHECKS['https']['url'])
            if CHECKS['https']['text'] in data:
                result |= HTTPS_NOCERT
                result |= HTTPS

        except Exception, e:
            logger.debug('HTTPS NoCert Check failed: %s', e)

    for hostname, ip in KNOWN_DNS.iteritems():
        try:
            if ip == socket.gethostbyname(hostname):
                result |= DNS

        except Exception, e:
            logger.debug('DNS Check failed: %s', e)

    for pastebin, bit in PASTEBINS.iteritems():
        try:
            data, code = ctx_nocert.get(
                pastebin,
                code=True, headers={'User-Agent': 'curl'}
            )
            if code == 200:
                result |= bit

        except Exception, e:
            logger.debug('Pastebin Check failed %s: %s', pastebin, e)

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

    try:
        nat, _, _ = stun.get_ip_info()
        for bit, descr in STUN_NAT_DESCRIPTION.iteritems():
            if descr == nat:
                result |= bit
                break

    except Exception, e:
        logger.debug('STUN Checks failed: %s', e)
        result |= STUN_NAT_BLOCKED

    try:
        offset = ntp_time_diff()
        result |= NTP
        if offset > 32767:
            offset = 32767
        elif offset < -32768:
            offset = -32768

    except Exception, e:
        logger.debug('NTP Checks failed: %s', e)
        offset = 0

    if sys.platform != 'win32':
        # This may cause firewall window
        # TODO: Work around this with pressing enter using keyboard module
        try:
            igdc = igd.IGDClient()
            if igdc.available:
                result |= IGD

        except Exception, e:
            logger.debug('IGD Check failed: %s', e)

    if mintime is None:
        mintime = 0
    else:
        mintime = int(mintime * 1000)
        if mintime > 65535:
            mintime = 65535

    ONLINE_STATUS = (offset, mintime, result)
    ONLINE_STATUS_CHECKED = time.time()

    logger.debug('Online check completed')
    return ONLINE_STATUS

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
        'stun': [
            descr for value,descr in STUN_NAT_DESCRIPTION.iteritems() if (
                (data & STUN_NAT_VALUE) == value
            )
        ][0],
        'ntp': bool(data & NTP),
        'pastebins': {
            pastebin:bool(data & bit) for pastebin,bit in PASTEBINS.iteritems()
        }
    }

class PortQuiz(threading.Thread):

    PORTQUIZ_ADDR='5.196.70.86'
    PORTQUIZ_HOSTNAME='portquiz.net'
    PORTQUIZ_443_MESSAGE='Your browser sent a request that this server could not understand'
    PORTQUIZ_MESSAGE='<html><body><h1>It works!</h1></body></html>'

    __slots__ = (
        'table', 'lock', 'abort', 'amount',
        'opener', 'http_timeout',
        'connect_timeout', 'available'
    )

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

        try:
            with self.lock:
                self.table['{}:{}'.format(host,port)] = sock
                sock.setblocking(1)
                sock.settimeout(self.http_timeout)

            response = self.opener.open('http://{}:{}'.format(host, port), timeout=self.http_timeout)
            data = response.read()
            if data.startswith(self.PORTQUIZ_MESSAGE) or port == 443 and self.PORTQUIZ_443_MESSAGE in data:
                self.available.append(port)
                if len(self.available) >= self.amount:
                    self.abort.set()

        except Exception, e:
            logger.debug('port check: %s:%s: %s', host, port, e)

        finally:
            try:
                sock.close()
            except:
                pass

    def _run(self):
        most_important = [
            80, 443, 8080, 53, 5222, 25, 110, 465
        ]

        try:
            portquiz_addr = socket.gethostbyname(self.PORTQUIZ_HOSTNAME)
        except socket.gaierror:
            portquiz_addr = self.PORTQUIZ_ADDR

        scan.scan([portquiz_addr], most_important, timeout=self.connect_timeout, abort=self.abort,
             on_open_port=self._on_open_port, pass_socket=True)

        if len(self.available) < self.amount:
            other = list([
                x for x in scan.TOP1000 if x not in most_important
            ])

            random.shuffle(other)

            scan.scan(
                [self.PORTQUIZ_ADDR], other, timeout=self.connect_timeout, abort=self.abort,
                on_open_port=self._on_open_port, pass_socket=True)

    def run(self):
        try:
            logger.debug('PortQuiz: started')
            self._run()
            logger.debug('PortQuiz: completed')

        except Exception, e:
            logger.exception('PortQuiz: %s', e)
