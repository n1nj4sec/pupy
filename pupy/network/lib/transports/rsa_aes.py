# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

""" This module contains an implementation of a simple xor transport for pupy. """

__all__ = ('RSA_AESClient', 'RSA_AESServer')

from ..base import BasePupyTransport, TransportError
import os
import traceback
import struct
import rsa
try:
    from Crypto import Random
except ImportError as e:
    Random=None
from cryptoutils.aes import NewAESCipher

from network.lib.buffer import Buffer
from network.lib import getLogger

BLOCK_SIZE = 16
CHUNK_SIZE = 4096

logger = getLogger('rsaaes')

class RSA_AESTransport(BasePupyTransport):
    """
    Implements a transport that simply apply a RSA_AES to each byte
    """
    password     = None
    iterations   = 1000
    key_size     = 32
    rsa_key_size = 4096
    aes_size     = 256

    __slots__ = (
        'aes_size', 'key_size',
        '_iv_enc', '_iv_dec',
        'enc_cipher', 'dec_cipher',
        'aes_key', 'size_to_read',
        'first_block', 'buffer'
    )

    def __init__(self, *args, **kwargs):
        super(RSA_AESTransport, self).__init__(*args, **kwargs)
        if self.aes_size == 256:
            self.key_size = 32
        elif self.aes_size == 128:
            self.key_size = 16
        else:
            raise TransportError("Only AES 256 and 128 are supported")

        if Random:
            self._iv_enc = Random.new().read(BLOCK_SIZE)
        else:
            self._iv_enc = os.urandom(BLOCK_SIZE)

        self.enc_cipher = None
        self.dec_cipher = None
        self._iv_dec = None
        self.aes_key = None
        self.size_to_read = None
        self.first_block = b""
        self.buffer = Buffer()

    def upstream_recv(self, data):
        try:
            with data:
                lctext = len(data)
                ltotal = lctext + 4
                lremainder = ltotal % BLOCK_SIZE
                if lremainder:
                    ltotal += BLOCK_SIZE - lremainder

                data.insert(struct.pack('<I', lctext))
                data.truncate(ltotal)

                if __debug__:
                    logger.debug('Send: cleartext len = %d padded+header = %d', lctext, len(data))

                data.write_to(
                    self.downstream,
                    modificator=self.enc_cipher.encrypt,
                    chunk_size=CHUNK_SIZE)

        except Exception as e:
            logger.debug(e)

    def downstream_recv(self, data):
        try:
            if __debug__:
                logger.debug('Recv data len=%d', len(data))

            if not self._iv_dec:
                if __debug__:
                    logger.debug('Read IV')

                if len(data) < BLOCK_SIZE:
                    if __debug__:
                        logger.debug('Read IV: Short read: %d < %d', len(data), BLOCK_SIZE)
                    return

                self._iv_dec = data.read(BLOCK_SIZE)
                self.dec_cipher = NewAESCipher(self.aes_key, self._iv_dec)

            while True:
                if not self.size_to_read:
                    if len(data) < BLOCK_SIZE:
                        if __debug__:
                            logger.debug('Read chunk header: Short read: %d < %d', len(data), BLOCK_SIZE)
                        break

                    self.first_block = self.dec_cipher.decrypt(data.read(BLOCK_SIZE))
                    self.size_to_read = struct.unpack_from('<I', self.first_block)[0]

                    if self.size_to_read == 0:
                        raise ValueError('Zero sized chunk')

                    if __debug__:
                        logger.debug('Read chunk header: expect: %d', self.size_to_read)

                if self.size_to_read <= len(self.first_block) - 4:
                    if __debug__:
                        logger.debug('Read chunk: consume small chunk')
                    # the remaining data is padding, just drop it
                    self.upstream.write(self.first_block[4:4+self.size_to_read])
                    self.size_to_read = 0
                    self.first_block = b''
                    continue

                if self.first_block:
                    if __debug__:
                        logger.debug('Read chunk: start: cleartext len = %d', self.size_to_read)

                    self.upstream.write(self.first_block[4:], notify=False)
                    self.size_to_read -= BLOCK_SIZE - 4
                    self.first_block = b''

                s = self.size_to_read

                if s % BLOCK_SIZE:
                    s += BLOCK_SIZE - (s % BLOCK_SIZE)

                lb = len(data)
                lb -= lb % BLOCK_SIZE

                while s and lb:
                    if __debug__:
                        logger.debug('Read chunk: required: %d available: %d', s, lb)

                    to_read = min(s, CHUNK_SIZE)
                    to_read = min(lb, to_read)

                    cleartext = self.dec_cipher.decrypt(data.read(to_read))
                    s -= to_read
                    lb -= to_read

                    if to_read >= self.size_to_read:
                        self.upstream.write(cleartext[:self.size_to_read])
                        self.size_to_read = 0

                        if __debug__:
                            logger.debug('Read chunk: chunk finished')

                    else:
                        self.upstream.write(cleartext, notify=False)
                        self.size_to_read -= to_read

                if not lb:
                    if __debug__:
                        logger.debug('Read chunk: No more data')

                    break

        except:
            logger.debug(traceback.format_exc())

class RSA_AESClient(RSA_AESTransport):
    __slots__ = (
        'pubkey', 'pubkey_path'
    )

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

        self.enc_cipher = NewAESCipher(self.aes_key, self._iv_enc)

        pkey = rsa.encrypt(self.aes_key, pk)
        self.downstream.write(pkey, notify=False)
        logger.debug('AES key crypted with RSA public key and sent to server (len=%d)', len(pkey))
        self.downstream.write(self._iv_enc)
        logger.debug('IV (len=%d) sent to Server', len(self._iv_enc))


class RSA_AESServer(RSA_AESTransport):
    __slots__ = (
        'privkey', 'privkey_path',
        'pk', 'post_handshake_callbacks'
    )

    privkey = None
    privkey_path = None

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
        self.pk = rsa.PrivateKey.load_pkcs1(self.privkey)
        self.post_handshake_callbacks=[]

    def downstream_recv(self, data):
        try:
            if self.aes_key is None: #receive aes key
                logger.debug('Read AES Key')

                expected = self.rsa_key_size/8
                if len(data) < expected:
                    logger.debug('Read AES Key: Short read: %d < %d', len(data), expected)
                    return

                cmsg = data.read(expected)

                try:
                    self.aes_key = rsa.decrypt(cmsg, self.pk)
                except rsa.pkcs1.DecryptionError:
                    logger.debug("decrypt failed")
                    self.close()
                    return

                self.enc_cipher = NewAESCipher(self.aes_key, self._iv_enc)
                logger.debug('client AES key received && decrypted from RSA private key')

                self.downstream.write(self._iv_enc) # send IV
                logger.debug('IV (len=%d) sent to Client', len(self._iv_enc))

                if self.buffer:
                    logger.debug('Flush buffer to client')
                    super(RSA_AESServer, self).upstream_recv(self.buffer)
                    self.buffer = None

            super(RSA_AESServer, self).downstream_recv(data)

        except Exception as e:
            logger.debug(e)

    def upstream_recv(self, data):
        if self.enc_cipher:
            super(RSA_AESServer, self).upstream_recv(data)
        else:
            data.write_to(self.buffer)
            logger.debug('Pending data: len=%d', len(self.buffer))
