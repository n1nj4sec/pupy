#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" wrapper around pycryptodome or pyaes depending on their availabilities """

__all__ = [
    'append_PKCS7_padding',
    'strip_PKCS7_padding',
    'NewAESCipher'
]

import logging

def append_PKCS7_padding(data):
    pad = 16 - (len(data) % 16)
    return data + chr(pad)*pad

def strip_PKCS7_padding(data):
    if len(data) % 16 != 0:
        raise ValueError("data is not padded !")

    padlen = ord(data[-1])

    if padlen > 16 or padlen < 1:
        raise ValueError("PKCS#7 invalid padding byte")
    if data[-padlen:]!=chr(padlen)*padlen:
        raise ValueError("PKCS#7 padding is invalid")
    return data[:-padlen]

try:
    from Crypto.Cipher import AES

    def NewAESCipher(aes_key, iv):
        return AES.new(aes_key, AES.MODE_CBC, iv)

except ImportError as e:
    logging.warning('pycrypto not available, using pure python libraries for AES (slower): %s', e)
    AES = None
    Random = None

    from .pyaes import AESModeOfOperationCBC

    class NewAESCipher(object):
        __slots__ = ('aes_key', 'iv', 'cipher')

        def __init__(self, aes_key, iv):
            self.aes_key = aes_key
            self.iv = iv
            self.cipher = AESModeOfOperationCBC(self.aes_key, iv=self.iv)

        def encrypt(self, data):
            """ data has to be padded """

            encrypted = []
            for i in range(0,len(data), 16):
                encrypted.append(self.cipher.encrypt(data[i:i+16]))

            return b''.join(encrypted)

        def decrypt(self, data):
            """ data has to be padded """

            cleartext = []

            for i in range(0,len(data), 16):
                cleartext.append(self.cipher.decrypt(data[i:i+16]))

            return b''.join(cleartext)
