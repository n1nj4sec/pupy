# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

""" This module contains an implementation of a simple xor transport for pupy. """

from ..base import BasePupyTransport, TransportError
import os, logging, threading, hashlib, traceback, traceback, struct
import rsa
try:
    from Crypto.Cipher import AES
    from Crypto import Random
    from Crypto.Hash import SHA256, HMAC
except ImportError as e:
    logging.warning("pycrypto not available, using pure python libraries (slower)")
    AES=None
    Random=None
    import cryptoutils.pyaes as pyaes

BLOCK_SIZE=16

class RSA_AESTransport(BasePupyTransport):
    """
    Implements a transport that simply apply a RSA_AES to each byte
    """
    password=None
    iterations=1000
    key_size=32
    rsa_key_size=4096
    aes_size=256
    def __init__(self, *args, **kwargs):
        super(RSA_AESTransport, self).__init__(*args, **kwargs)
        if self.aes_size==256:
            self.key_size=32
        elif self.aes_size==128:
            self.key_size=16
        else:
            raise TransportError("Only AES 256 and 128 are supported")
        if Random:
            self._iv_enc = Random.new().read(BLOCK_SIZE)
        else:
            self._iv_enc = os.urandom(BLOCK_SIZE)
        self.enc_cipher = None
        self.dec_cipher = None
        self._iv_dec = None
        self.aes_key=None
        self.size_to_read=None
        self.first_block=b""

    def on_connect(self):
        self.downstream.write(self._iv_enc) # send IV

    def upstream_recv(self, data):
        try:
            cleartext=data.peek()
            tosend=b""
            i=0
            packed_size=struct.pack("<I", len(cleartext))
            tosend=packed_size+cleartext
            tosend+=b"\x00"*(BLOCK_SIZE - (len(tosend)%BLOCK_SIZE))
            data.drain(len(cleartext))
            self.downstream.write(self.enc_cipher.encrypt(tosend))
        except Exception as e:
            logging.debug(e)


    def downstream_recv(self, data):
        try:
            enc=data.peek()
            if self._iv_dec is None: #receive IV
                if len(enc)<BLOCK_SIZE:
                    return
                self._iv_dec=enc[0:BLOCK_SIZE]
                if AES is not None:
                    self.dec_cipher = AES.new(self.aes_key, AES.MODE_CBC, self._iv_dec)
                else:
                    self.dec_cipher = pyaes.AESModeOfOperationCBC(self.aes_key, iv = self._iv_dec)
                data.drain(BLOCK_SIZE)
                enc=enc[BLOCK_SIZE:]
                if not enc:
                    return
            i=0
            cleartext=b""
            full_block=b""
            while True:
                if self.size_to_read is None:
                    if len(enc)<BLOCK_SIZE:
                        break
                    self.first_block=self.dec_cipher.decrypt(enc[0:BLOCK_SIZE])
                    data.drain(BLOCK_SIZE)
                    self.size_to_read=struct.unpack("<I", self.first_block[0:4])[0]
                    enc=enc[BLOCK_SIZE:]
                if self.size_to_read is None:
                    break
                if self.size_to_read <= len(self.first_block[4:]):
                    cleartext+=self.first_block[4:4+self.size_to_read] # the remaining data is padding, just drop it
                    self.size_to_read=None
                    self.first_block=b""
                    continue
                s=(self.size_to_read-len(self.first_block[4:]))
                blocks_to_read=s+(BLOCK_SIZE-(s%BLOCK_SIZE))
                if len(enc) < blocks_to_read:
                    break
                full_block=self.first_block[4:]+self.dec_cipher.decrypt(enc[:blocks_to_read])
                cleartext+=full_block[0:self.size_to_read] # the remaining data is padding, just drop it
                enc=enc[blocks_to_read:]
                data.drain(blocks_to_read)
                self.size_to_read=None
                self.first_block=b""
            self.upstream.write(cleartext)
        except Exception as e:
            logging.debug(traceback.format_exc())

class RSA_AESClient(RSA_AESTransport):
    pubkey=None
    pubkey_path=None
    def __init__(self, *args, **kwargs):
        super(RSA_AESClient, self).__init__(*args, **kwargs)
        if "pubkey" in kwargs:
            self.pubkey=kwargs["pubkey"]
        if "pubkey_path" in kwargs:
            self.pubkey_path=kwargs["pubkey_path"]
        if self.pubkey_path:
            self.pubkey=open(self.pubkey_path).read()
        if self.pubkey is None:
            raise TransportError("A public key (pem format) needs to be supplied for RSA_AESClient")

    def on_connect(self):
        pk = rsa.PublicKey.load_pkcs1(self.pubkey)
        if Random:
            self.aes_key = Random.new().read(self.key_size)
        else:
            self.aes_key = os.urandom(self.key_size)

        if AES is not None:
            self.enc_cipher = AES.new(self.aes_key, AES.MODE_CBC, self._iv_enc)
        else:
            self.enc_cipher = pyaes.AESModeOfOperationCBC(self.aes_key, iv = self._iv_enc)
        self.downstream.write(rsa.encrypt(self.aes_key, pk))
        self.downstream.write(self._iv_enc)

        

class RSA_AESServer(RSA_AESTransport):
    privkey=None
    privkey_path=None
    def __init__(self, *args, **kwargs):
        super(RSA_AESServer, self).__init__(*args, **kwargs)
        if "privkey" in kwargs:
            raise TransportError("You need to pass privatekeys as a path or it could be usafe and embedded in payloads")
        if "privkey_path" in kwargs:
            self.privkey_path=kwargs["privkey_path"]
        if self.privkey_path:
            self.privkey=open(self.privkey_path).read()
        if self.privkey is None:
            raise TransportError("A private key (pem format) needs to be supplied for RSA_AESServer")
        self.pk=rsa.PrivateKey.load_pkcs1(self.privkey)

    def downstream_recv(self, data):
        try:
            enc=data.peek()
            if self.aes_key is None: #receive aes key
                if len(enc) < self.rsa_key_size/8:
                    return
                cmsg=enc[:self.rsa_key_size/8]
                try:
                    self.aes_key=rsa.decrypt(cmsg, self.pk)
                except rsa.pkcs1.DecryptionError:
                    self.close()
                    return
                data.drain(self.rsa_key_size/8)

                if AES is not None:
                    self.enc_cipher = AES.new(self.aes_key, AES.MODE_CBC, self._iv_enc)
                else:
                    self.enc_cipher = pyaes.AESModeOfOperationCBC(self.aes_key, iv = self._iv_enc)
            super(RSA_AESServer, self).downstream_recv(data)
        except Exception as e:
            logging.debug(e)
    def upstream_recv(self, data):
        if self.enc_cipher is None:
            return
        super(RSA_AESServer, self).upstream_recv(data)


