#!/usr/bin/env python

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
__all__ = (
    'InvalidHostName', 'SecureDNS', 'A', 'AAAA',
    'GOOGLE', 'CLOUDFLARE', 'QUAD9', 'QUAD9_IP'
)

from json import loads

from . import tinyhttp
import socket


# Resource Record Types
A = 1
AAAA = 28

# DNS status codes
NOERROR = 0

UNRESERVED_CHARS = \
    'abcdefghijklmnopqrstuvwxyz' \
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ' \
    '0123456789-._~'


# Providers
GOOGLE = 'https://dns.google.com/resolve'
CLOUDFLARE = 'https://cloudflare-dns.com/dns-query'
# Unstable
QUAD9 = 'https://dns.quad9.net:5053/dns-query'
QUAD9_IP = 'https://9.9.9.9:5053/dns-query'

NEXTDNS_1 = 'https://dns1.nextdns.io/dns-query'
NEXTDNS_2 = 'https://dns2.nextdns.io/dns-query'
# Down
# CZNIC = 'https://odvr.nic.cz/doh'

PROVIDERS = (
    GOOGLE, CLOUDFLARE, QUAD9_IP, QUAD9,
    NEXTDNS_1, NEXTDNS_2
)


class InvalidHostName(Exception):
    pass


class SecureDNS(object):
    __slots__ = ('client', 'url', 'cd')

    '''Resolve domains using Google's Public DNS-over-HTTPS API'''

    @staticmethod
    def available(hostname, ipv6, *expected_ips):
        qtype = AAAA if ipv6 else A

        for provider in PROVIDERS:
            dns = SecureDNS(provider)
            try:
                resolved = dns.resolve(hostname, qtype)
                if not resolved:
                    continue

            except (IOError, OSError, socket.error):
                continue

            if not expected_ips:
                return dns

            if set(expected_ips) == set(resolved):
                return dns

    def __init__(self, url=GOOGLE, validation=False):
        self.client = tinyhttp.HTTP()
        self.url = url
        # Validation enabled
        self.cd = 0 if bool(validation) else 1

    def resolve(self, hostname, query_type=A):
        '''return ip address(es) of hostname'''

        payload, code = self.client.get(
            self.url, code=True,
            headers={
                'Accept': 'application/dns-json'
            },
            params={
                'cd': self.cd,
                'type': query_type,
                'name': self._prepare_hostname(hostname),
            },
        )

        if code != 200:
            return None

        response = loads(payload)

        if response['Status'] == NOERROR:
            answers = []
            for answer in response['Answer']:
                name, response_type, ttl, data = \
                    map(answer.get, ('name', 'type', 'ttl', 'data'))
                if response_type in (A, AAAA):
                    answers.append(str(data))

            if answers == []:
                return None

            return answers

    def _prepare_hostname(self, hostname):
        '''verify the hostname is well-formed'''
        hostname = hostname.rstrip('.')  # strip trailing dot if present

        if not(1 <= len(hostname) <= 253):  # test length of hostname
            raise InvalidHostName()

        for label in hostname.split('.'):  # test length of each label
            if not(1 <= len(label) <= 63):
                raise InvalidHostName()
        try:
            return hostname.encode('ascii')

        except UnicodeEncodeError:
            raise InvalidHostName()

    def __repr__(self):
        return 'SecureDNS({}, {})'.format(
            repr(self.url), bool(self.cd)
        )
