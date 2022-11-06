#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

__all__ = (
    'append_PKCS7_padding',
    'strip_PKCS7_padding',
    'NewAESCipher', 'AES_BLOCK_SIZE',
    'AES_MODE_CTR', 'AES_MODE_CFB', 'AES_MODE_CBC'
)

import logging
import sys

if sys.version_info.major > 2:
    xrange = range
    long = int

    def to_byte(x):
        return bytes((x,))

    def from_byte(x):
        return x

else:
    def to_byte(x):
        return chr(x)

    def from_byte(x):
        return ord(x)


AES_BLOCK_SIZE = 16


def append_PKCS7_padding(data):
    pad = AES_BLOCK_SIZE - (len(data) % AES_BLOCK_SIZE)
    return data + to_byte(pad)*pad


def strip_PKCS7_padding(data):
    if len(data) % AES_BLOCK_SIZE != 0:
        raise ValueError('data is not padded')

    padlen = from_byte(data[-1])

    if padlen > AES_BLOCK_SIZE or padlen < 1:
        raise ValueError('PKCS#7 invalid padding byte')

    if data[-padlen:] != to_byte(padlen) * padlen:
        raise ValueError('PKCS#7 padding is invalid')

    return data[:-padlen]


try:
    from Crypto.Cipher import AES
    from Crypto.Util import Counter

    AES_MODE_CTR = AES.MODE_CTR
    AES_MODE_CFB = AES.MODE_CFB
    AES_MODE_CBC = AES.MODE_CBC

    def NewAESCipher(aes_key, iv, mode=AES_MODE_CBC):
        if mode == AES_MODE_CTR:
            if type(iv) not in (int, long):
                iv = long(iv.encode('hex'), 16)

            counter = Counter.new(
                nbits=AES.block_size*8,
                initial_value=iv
            )
            return AES.new(aes_key, mode, counter=counter)

        return AES.new(aes_key, mode, IV=iv)

except ImportError as e:
    logging.warning(
        'pycrypto not available, using pure python '
        'libraries for AES (slower): %s', e
    )

    AES_MODE_CTR = 0
    AES_MODE_CFB = 1
    AES_MODE_CBC = 2

    try:
        from pyaes import (
            AESModeOfOperationCBC, AESModeOfOperationCFB,
            AESModeOfOperationCTR, Counter
        )
    except ImportError as e:
        logging.exception('pyaes is missing: %s', e)
        raise e

    class NewAESCipher(object):
        __slots__ = ('aes_key', 'iv', 'cipher', 'mode')

        def __init__(self, aes_key, iv, mode=AES_MODE_CBC):
            self.aes_key = aes_key
            self.iv = iv
            self.mode = mode
            if mode == AES_MODE_CBC:
                self.cipher = AESModeOfOperationCBC(self.aes_key, iv=self.iv)
            elif mode == AES_MODE_CFB:
                self.cipher = AESModeOfOperationCFB(self.aes_key, iv=self.iv)
            elif mode == AES_MODE_CTR:
                if type(iv) not in (int, long):
                    iv = long(iv.encode('hex'), 16)

                self.iv = Counter(initial_value=iv)
                self.cipher = AESModeOfOperationCTR(
                    self.aes_key, counter=self.iv
                )

        def encrypt(self, data):
            """ data has to be padded """

            if self.mode == AES_MODE_CTR:
                return self.cipher.encrypt(data)

            encrypted = []
            for i in xrange(0, len(data), AES_BLOCK_SIZE):
                encrypted.append(
                    self.cipher.encrypt(data[i:i+AES_BLOCK_SIZE]))

            return b''.join(encrypted)

        def decrypt(self, data):
            """ data has to be padded """

            if self.mode == AES_MODE_CTR:
                return self.cipher.decrypt(data)

            cleartext = []

            for i in xrange(0, len(data), AES_BLOCK_SIZE):
                cleartext.append(
                    self.cipher.decrypt(data[i:i+AES_BLOCK_SIZE]))

            return b''.join(cleartext)
