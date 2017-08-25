2# -*- coding: utf-8 -*-

""" EC4 PSK transport """

from ..base import BasePupyTransport, TransportError
from ...lib.picocmd.ecpv import ECPV

import struct
import time
import random

from Crypto.Cipher import ARC4

from hashlib import sha384

class EC4TransportServer(BasePupyTransport):
    privkey = None

    def __init__(self, *args, **kwargs):
        super(EC4TransportServer, self).__init__(*args, **kwargs)
        if not self.privkey:
            raise ValueError('Private key required for EC4')

        self.encoder = ECPV(
            curve='brainpoolP384r1',
            private_key=self.privkey,
            hash=sha384
        )

        self.encryptor = None
        self.decryptor = None
        self.up_buffer = ''

    def downstream_recv(self, data):
        if not self.encryptor:
            if len(data) < 2:
                return

            length, = struct.unpack_from('H', data.peek(2))
            if len(data) < 2 + length:
                return

            request = data.read(2 + length)

            response, key = self.encoder.process_kex_request(request[2:], 0, key_size=128)

            # Add jitter, tinyec is quite horrible
            time.sleep(random.random())
            self.downstream.write(struct.pack('H', len(response)) + response)

            self.encryptor = ARC4.new(key=key[0])
            self.decryptor = ARC4.new(key=key[1])

            # https://wikileaks.org/ciav7p1/cms/files/NOD%20Cryptographic%20Requirements%20v1.1%20TOP%20SECRET.pdf
            # Okay...
            self.encryptor.encrypt('\x00'*3072)
            self.decryptor.decrypt('\x00'*3072)

            if len(data):
                rcv = self.decryptor.decrypt(data.read())
                self.upstream.write(rcv)

            if self.up_buffer:
                self.downstream.write(self.encryptor.encrypt(self.up_buffer))
                self.up_buffer = ''

        else:
            rcv = self.decryptor.decrypt(data.read())
            self.upstream.write(rcv)

    def upstream_recv(self, data):
        snd = data.read()
        if not self.encryptor:
            self.up_buffer = self.up_buffer + snd
        else:
            self.downstream.write(self.encryptor.encrypt(snd))


class EC4TransportClient(BasePupyTransport):
    pubkey = None

    def __init__(self, *args, **kwargs):
        super(EC4TransportClient, self).__init__(*args, **kwargs)
        if not self.pubkey:
            raise ValueError('Public key required for EC4')

        self.encoder = ECPV(
            curve='brainpoolP384r1',
            public_key=self.pubkey,
            hash=sha384
        )

        self.encryptor = None
        self.decryptor = None
        self.up_buffer = ''

    def on_connect(self):
        req = self.encoder.generate_kex_request()
        self.downstream.write(
            struct.pack('H', len(req)) + req
        )

    def downstream_recv(self, data):
        if not self.encryptor:
            if len(data) < 2:
                return

            length, = struct.unpack_from('H', data.peek(2))
            if len(data) < 2 + length:
                return

            response = data.read(2+length)

            key = self.encoder.process_kex_response(response[2:], 0, key_size=128)

            self.encryptor = ARC4.new(key=key[0])
            self.decryptor = ARC4.new(key=key[1])

            self.encryptor.encrypt('\x00'*3072)
            self.decryptor.decrypt('\x00'*3072)

            if len(data):
                rcv = self.decryptor.decrypt(data.read())
                self.upstream.write(rcv)

            if self.up_buffer:
                self.downstream.write(self.encryptor.encrypt(self.up_buffer))
                self.up_buffer = ''

        else:
            rcv = self.decryptor.decrypt(data.read())
            self.upstream.write(rcv)

    def upstream_recv(self, data):
        snd = data.read()

        if not self.encryptor:
            self.up_buffer = self.up_buffer + snd
        else:
            self.downstream.write(self.encryptor.encrypt(snd))
