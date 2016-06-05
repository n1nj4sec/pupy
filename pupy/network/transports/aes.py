# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

""" This module contains an implementation of a simple xor transport for pupy. """

from ..base import BasePupyTransport, TransportError
import logging
import traceback
import hashlib
import os
try:
    #raise ImportError()
    from Crypto.Cipher import AES
    from Crypto import Random
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Hash import SHA256, HMAC
except ImportError as e:
    logging.warning("pycrypto not available, using pure python libraries (slower)")
    PBKDF2=None
    AES=None
    Random=None
    from cryptoutils.pbkdf2 import pbkdf2_bin
    import cryptoutils.pyaes as pyaes

BLOCK_SIZE=16

class AESTransport(BasePupyTransport):
    """
    Implements a transport that simply apply a AES to each byte
    """
    password=None
    iterations=1000
    key_size=32

    def __init__(self, *args, **kwargs):
        super(AESTransport, self).__init__(*args, **kwargs)
        if "password" in kwargs:
            self.password=kwargs["password"]
        if self.password is None:
            raise TransportError("A password needs to be supplied for AES")
        self._salt = "__PupY_PBKDF2_S4l7__"
        logging.debug("deriving the key with %s iterations..."%self.iterations)
        if PBKDF2 is not None:
            self._derived_key = PBKDF2(self.password, self._salt, self.key_size, self.iterations, prf=lambda password, salt: HMAC.new(password, salt, SHA256).digest())
        else:
            self._derived_key = pbkdf2_bin(self.password, self._salt, keylen=self.key_size, iterations=self.iterations, hashfunc=hashlib.sha256)
        logging.debug("key derived ...")
        if Random:
            self._iv_enc = Random.new().read(BLOCK_SIZE)
        else:
            self._iv_enc = os.urandom(BLOCK_SIZE)
        if AES is not None:
            self.enc_cipher = AES.new(self._derived_key, AES.MODE_CBC, self._iv_enc)
        else:
            self.enc_cipher = pyaes.AESModeOfOperationCBC(self._derived_key, iv = self._iv_enc)
        self.dec_cipher = None
        self._iv_dec = None

    def on_connect(self):
        self.downstream.write(self._iv_enc) # send IV

    def upstream_recv(self, data):
        try:
            cleartext=data.peek()
            tosend=b""
            i=0
            while True:
                b=cleartext[i:i+BLOCK_SIZE-1]
                i+=BLOCK_SIZE-1
                if not b:
                    break
                b=chr(len(b))+b
                b+=b"\x00"*(BLOCK_SIZE-len(b))
                tosend+=self.enc_cipher.encrypt(b)
            data.drain(len(cleartext))
            self.downstream.write(tosend)
        except Exception as e:
            logging.debug(e)

    def downstream_recv(self, data):
        try:
            enc=data.peek()
            if self._iv_dec is None: #receive IV
                if len(data)<BLOCK_SIZE:
                    return
                self._iv_dec=enc[0:BLOCK_SIZE]
                if AES is not None:
                    self.dec_cipher = AES.new(self._derived_key, AES.MODE_CBC, self._iv_dec)
                else:
                    self.dec_cipher = pyaes.AESModeOfOperationCBC(self._derived_key, iv = self._iv_dec)
                data.drain(BLOCK_SIZE)
                enc=enc[BLOCK_SIZE:]
                if not enc:
                    return
            i=0
            cleartext=b""
            while True:
                b=enc[i:i+BLOCK_SIZE]
                i+=BLOCK_SIZE
                if len(b)!=BLOCK_SIZE:
                    break
                data.drain(len(b))
                d=self.dec_cipher.decrypt(b)
                size=ord(d[0])
                cleartext+=d[1:1+size]
            self.upstream.write(cleartext)
        except Exception as e:
            logging.debug(e)

class AESClient(AESTransport):
    pass
class AESServer(AESTransport):
    pass
class AES256(AESTransport):
    key_size=32
class AES128(AESTransport):
    key_size=16

