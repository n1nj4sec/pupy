#!/usr/bin/env python
# -*- coding: UTF8 -*-

""" wrapper around pycryptodome or pyaes depending on their availabilities """

import logging

try:
    from Crypto.Cipher import AES
except ImportError as e:
    logging.warning("pycrypto not available, using pure python libraries for AES (slower)")
    AES=None
    Random=None
from .pyaes import AESModeOfOperationCBC

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

class NewAESCipher(object):
    def __init__(self, aes_key, iv, pyaes=False):
        self.aes_key=aes_key
        self.iv=iv
        self.pyaes=pyaes
        if AES is not None and not self.pyaes:
            self.cipher = AES.new(self.aes_key, AES.MODE_CBC, self.iv)
            self.pyaes=False
        else:
            self.cipher = AESModeOfOperationCBC(self.aes_key, iv = self.iv)
            self.pyaes=True

    def encrypt(self, data):
        """ data has to be padded """
        #data=append_PKCS7_padding(data)
        if not self.pyaes:
            return self.cipher.encrypt(data)
        else: #pyaes doesn't handle multi block enc/dec
            encrypted=b""
            for i in range(0,len(data), 16):
                encrypted+=self.cipher.encrypt(data[i:i+16])
            return encrypted

    def decrypt(self, data):
        """ data has to be padded """
        cleartext=b""
        if not self.pyaes:
            cleartext=self.cipher.decrypt(data)
        else: #pyaes doesn't handle multi block enc/dec
            for i in range(0,len(data), 16):
                cleartext+=self.cipher.decrypt(data[i:i+16])
        #cleartext=strip_PKCS7_padding(cleartext)
        return cleartext
