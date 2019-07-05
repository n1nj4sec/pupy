#!/usr/bin/env python

__all__ = (
    'InvalidHostName', 'SecureDNS', 'A', 'AAAA'
)

from urllib import urlencode
from random import randint, choice
from json import loads

import tinyhttp

# Resource Record Types
A = 1
AAAA = 28

# DNS status codes
NOERROR = 0

UNRESERVED_CHARS = \
    'abcdefghijklmnopqrstuvwxyz' \
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ' \
    '0123456789-._~'


class InvalidHostName(Exception):
    pass


class SecureDNS(object):
    __slots__ = ('client', 'url', 'cd', 'edns_client_subnet')

    '''Resolve domains using Google's Public DNS-over-HTTPS API'''

    def __init__(self, cd=False, edns_client_subnet='0.0.0.0/0'):
        self.client = tinyhttp.HTTP()
        self.url = 'https://dns.google.com/resolve'
        self.cd = cd
        self.edns_client_subnet = edns_client_subnet

    def resolve(self, hostname, query_type=A):
        '''return ip address(es) of hostname'''

        hostname = self._prepare_hostname(hostname)
        params = {
            'cd': self.cd,
            'type': query_type,
            'edns_client_subnet': self.edns_client_subnet,
            'name': hostname,
            'random_padding': self._generate_padding()
        }

        payload, code = self.client.get(
            self.url + '?' + urlencode(params), code=True
        )

        if code == 200:
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

        return None

    def _prepare_hostname(self, hostname):
        '''verify the hostname is well-formed'''
        hostname = hostname.rstrip('.')  # strip trailing dot if present

        if not(1 <= len(hostname) <= 253):  # test length of hostname
            raise InvalidHostName

        for label in hostname.split('.'):  # test length of each label
            if not(1 <= len(label) <= 63):
                raise InvalidHostName
        try:
            return hostname.encode('ascii')

        except UnicodeEncodeError:
            raise InvalidHostName

    def _generate_padding(self):
        '''generate a pad using unreserved chars'''
        pad_len = randint(10, 50)
        return ''.join(choice(UNRESERVED_CHARS) for _ in range(pad_len))
