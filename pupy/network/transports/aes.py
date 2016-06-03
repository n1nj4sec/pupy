# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

""" This module contains an implementation of a simple xor transport for pupy. """

from ..base import BasePupyTransport, TransportError
import logging
import traceback
import hashlib
try:
    from Crypto.Cipher import AES
    from Crypto import Random
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Hash import SHA256
except ImportError as e:
    logging.warning(e)

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
        self._derived_key = PBKDF2(self.password, self._salt, self.key_size, self.iterations)
        logging.debug("key derived ...")
        self._iv_enc = Random.new().read(AES.block_size)
        self.enc_cipher = AES.new(self._derived_key, AES.MODE_CBC, self._iv_enc)
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
                b=cleartext[i:i+AES.block_size-1]
                i+=AES.block_size-1
                if not b:
                    break
                b=chr(len(b))+b
                b+=b"\x00"*(AES.block_size-len(b))
                tosend+=self.enc_cipher.encrypt(b)
            data.drain(len(cleartext))
            self.downstream.write(tosend)
        except Exception as e:
            logging.debug(e)

    def downstream_recv(self, data):
        try:
            enc=data.peek()
            if self._iv_dec is None: #receive IV
                if len(data)<AES.block_size:
                    return
                self._iv_dec=enc[0:AES.block_size]
                self.dec_cipher = AES.new(self._derived_key, AES.MODE_CBC, self._iv_dec)
                data.drain(AES.block_size)
                enc=enc[AES.block_size:]
                if not enc:
                    return
            i=0
            cleartext=b""
            while True:
                b=enc[i:i+AES.block_size]
                i+=AES.block_size
                if len(b)!=AES.block_size:
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

