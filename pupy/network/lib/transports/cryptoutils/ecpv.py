# -*- coding: utf-8 -*-

import struct
import base64

from collections import deque

from tinyec.registry import get_curve
from tinyec.ec import (
    to_bytes, from_bytes,
    ec2osp, osp2ec
)

from . import (
    NewAESCipher, get_random,
    SHA1, SHA3_256, SHA3_512,
    AES_BLOCK_SIZE,
    AES_MODE_CTR, AES_MODE_CFB
)


class PubKeyCache(object):
    __slots__ = ('records',)

    def __init__(self, maxlen=64):
        self.records = deque(maxlen=maxlen)

    def get(self, get_key):
        for (key, value) in self.records:
            if key == get_key:
                return value

    def set(self, set_key, pubkey):
        for (key, value) in self.records:
            if key == set_key:
                return value

        self.records.append((set_key, pubkey))
        return pubkey


_PUBKEY_CACHE = PubKeyCache()


class ECPV(object):
    __slots__ = (
        '_curve', '_hash',
        '_private_key', '_public_key', '_kex_shared_key',
        '_kex_public_key', '_kex_private_key',
        '_public_key_digest', '_cached_kex_request',
        '_cached_kex_response', '_mgf_size'
    )

    def __init__(self, curve='brainpoolP160r1', hash=None, private_key=None, public_key=None):
        if not hash:
            if '160' in curve:
                hash = SHA1
            elif '224' in curve:
                hash = SHA3_256
            elif '256' in curve:
                hash = SHA3_256
            elif '384' in curve:
                hash = SHA3_512
            elif '521' in curve:
                hash = SHA3_512
            else:
                raise ValueError('Appropriate hash should be specified')

            if hash is None:
                raise ValueError('Hash is unsupported (native only?)')

        self._curve = get_curve(curve)

        self._hash = hash

        # Check that hash is properly initialized
        self._hash.new()

        try:
            self._mgf_size = self._hash.new().block_size
        except AttributeError:
            self._mgf_size = self._hash.digest_size

        if not self._mgf_size >= self._curve.bytes:
            raise ValueError('Incompatible hash function')

        if private_key:
            self._private_key = from_bytes(base64.decodestring(private_key))
        else:
            self._private_key = None

        if private_key and not public_key:
            record = _PUBKEY_CACHE.get(self._private_key)
            if record:
                self._public_key, self._public_key_digest = record
            else:
                self._public_key = self._curve.g * self._private_key
                self._public_key.precompute()
                self._public_key_digest = self._mgf2(ec2osp(self._public_key), AES_BLOCK_SIZE)
                _PUBKEY_CACHE.set(self._private_key, (self._public_key, self._public_key_digest))

        elif public_key:
            record = _PUBKEY_CACHE.get(public_key)
            if record:
                self._public_key, self._public_key_digest = _PUBKEY_CACHE.get(public_key)
            else:
                self._public_key = osp2ec(self._curve, base64.decodestring(public_key))
                self._public_key.precompute()
                self._public_key_digest = self._mgf2(ec2osp(self._public_key), AES_BLOCK_SIZE)
                _PUBKEY_CACHE.set(public_key, (self._public_key, self._public_key_digest))
        else:
            self._public_key = None
            self._public_key_digest = None

        self._kex_shared_key = None
        self._kex_public_key = None
        self._kex_private_key = None

        self._cached_kex_request = None
        self._cached_kex_response = None

    @property
    def kex_completed(self):
        return not (self._kex_shared_key is None)

    @property
    def encryption_key(self):
        return self._kex_shared_key[0] if self._kex_shared_key else self._public_key_digest

    @property
    def decryption_key(self):
        return self._kex_shared_key[1] if self._kex_shared_key else self._public_key_digest

    def kex_reset(self):
        self._kex_shared_key = None
        self._kex_public_key = None
        self._kex_private_key = None

    def clone(self):
        clone = ECPV()
        clone._curve = self._curve
        clone._hash = self._hash
        clone._private_key = self._private_key
        clone._public_key = self._public_key
        clone._public_key_digest = self._public_key_digest
        clone._kex_shared_key = None
        clone._kex_public_key = None
        clone._kex_private_key = None
        return clone


    def _gen_random(self):
        value = None
        while not value > 1 and value < self._curve.field.n:
            value = from_bytes(get_random(self._curve.bytes))
        return value


    def _mgf2(self, value, length):
        result = []
        hash = self._hash.new()
        k = length / self._mgf_size + 1
        for i in xrange(1, k + 1):
            hash.update(value + struct.pack('>I', i))
            result.append(hash.digest())
            hash = self._hash.new()

        return ''.join(result)[:length]


    def generate_key(self):
        self._private_key = self._gen_random()
        self._public_key = self._curve.g * self._private_key
        self._public_key_digest = self._mgf2(ec2osp(self._public_key), AES_BLOCK_SIZE)

        return (
            base64.b64encode(to_bytes(self._private_key)),
            base64.b64encode(ec2osp(self._public_key))
        )


    def pack(self, message, nonce=None):
        if not self._private_key:
            raise ValueError('No private key')
        t = 0
        k = 0
        s = 0
        r = ''
        while not (t and s):
            k = self._gen_random()
            R = self._curve.g * k
            key = self._mgf2(ec2osp(R), 16)

            r = self.encrypt(message, nonce, key=key)

            hash = self._hash.new()
            hash.update(r + (
                struct.pack('>I', nonce) if nonce else b''
            ) + struct.pack('>I', len(r)))
            u = hash.digest()[:self._curve.bytes]
            t = from_bytes(u)
            if not (t > 1 and t < self._curve.field.n):
                continue

            s = (k - self._private_key * t) % self._curve.field.n

        bytes = to_bytes(s)
        if len(bytes) != self._curve.bytes:
            bytes = bytes + '\x00' * (self._curve.bytes - len(bytes))

        return bytes + r


    def unpack(self, message, nonce=None):
        if not self._public_key:
            raise ValueError('No public key')
        s = from_bytes(message[:self._curve.bytes])
        r = message[self._curve.bytes:]
        hash = self._hash.new()
        hash.update(r + (
            struct.pack('>I', nonce) if nonce else b''
        ) + struct.pack('>I', len(r)))
        u = hash.digest()[:self._curve.bytes]
        t = from_bytes(u)
        if not (t >= 0 and t < self._curve.field.n):
            return None
        R = self._curve.g * s + self._public_key * t
        if R.inf:
            return None
        key = self._mgf2(ec2osp(R), 16)

        return self.decrypt(r, nonce, key=key)


    def generate_kex_request(self):
        self._kex_private_key = self._gen_random()
        self._kex_public_key = self._curve.g * self._kex_private_key
        return ec2osp(self._kex_public_key)


    def process_kex_request(self, request, nonce=None, encrypt=False, key_size=AES_BLOCK_SIZE):
        if request == self._cached_kex_request and self._kex_shared_key:
            return self._cached_kex_response, self._kex_shared_key

        self._cached_kex_request = request
        response = self.generate_kex_request()
        self.process_kex_response(request, nonce=nonce, decrypt=False, key_size=key_size)
        self._kex_shared_key = list(x for x in reversed(self._kex_shared_key))
        self._cached_kex_response = \
          self.pack(response, nonce) if encrypt else response
        return self._cached_kex_response, self._kex_shared_key


    def process_kex_response(self, response, nonce=None, decrypt=False, key_size=AES_BLOCK_SIZE):
        if decrypt:
            response = self.unpack(response, nonce)
        P1 = osp2ec(self._curve, response)
        key = self._mgf2(ec2osp(P1 * self._kex_private_key), key_size)
        self._kex_shared_key = (key, b''.join(reversed(key)))
        return self._kex_shared_key

    def check_csum(self, message, nonce, csum, key=None):
        if not key:
            if self._kex_shared_key:
                key = self._kex_shared_key[1]
            else:
                key = self._public_key_digest

        h = SHA1.new()
        h.update(key)
        h.update(message)
        h.update(to_bytes(len(message)))
        h.update(to_bytes(nonce))

        csum2 = h.digest()[:4]
        return csum == csum2

    def gen_csum(self, message, nonce, key=None):
        if not key:
            if self._kex_shared_key:
                key = self._kex_shared_key[0]
            else:
                key = self._public_key_digest

        h = SHA1.new()
        h.update(key)
        h.update(message)
        h.update(to_bytes(len(message)))
        h.update(to_bytes(nonce))

        csum = h.digest()[:4]
        return csum

    def encrypt(self, message, nonce, key=None):
        if not key:
            if self._kex_shared_key:
                key = self._kex_shared_key[0]
            else:
                key = self._public_key_digest

        if nonce is not None:
            encrypted = NewAESCipher(
                key, nonce, AES_MODE_CTR
            ).encrypt(message)
        else:
            bs = AES_BLOCK_SIZE
            iv = get_random(AES_BLOCK_SIZE)
            length = struct.pack('>I', len(message))
            pad = (bs - (len(message) + len(length))%bs) % bs
            padding = struct.pack('B', pad)*pad
            encrypted = iv + NewAESCipher(
                key, iv, AES_MODE_CFB
            ).encrypt(length + message + padding)

        return encrypted


    def decrypt(self, message, nonce, key=None):
        if not key:
            if self._kex_shared_key:
                key = self._kex_shared_key[1]
            else:
                key = self._public_key_digest

        if nonce is not None:
            decrypted = NewAESCipher(
                key, nonce, AES_MODE_CTR
            ).decrypt(message)
        else:
            bs = AES_BLOCK_SIZE
            iv, body = message[:bs], message[bs:]

            payload = NewAESCipher(
                key, iv, AES_MODE_CFB
            ).decrypt(body)

            length = struct.unpack_from('>I', payload)[0]
            message = payload[4:]
            pad = len(message) - length
            decrypted, padding = message[:length], message[length:]
            if not padding == struct.pack('B', pad)*pad:
                return None

        return decrypted


    def encode(self, message, nonce, symmetric = False):
        if symmetric:
            return self.encrypt(message, nonce)
        return self.pack(message, nonce)


    def decode(self, message, nonce, symmetric = False):
        if symmetric:
            return self.decrypt(message, nonce)
        return self.unpack(message, nonce)


__all__ = (PubKeyCache, ECPV)


if __name__ == '__main__':
    for x in xrange(1, 10):
        x = ECPV(curve='brainpoolP384r1')

        x._curve.g * (1 << 47)

        priv, pub = x.generate_key()
        print "PRIV:", priv
        print "PUB:", pub
        msg = 'Hello, world'
        msg2 = x.decode(x.encode(msg, 0), 0)
        if not msg == msg2:
            print "VRFY1 FAIL: ", msg2
            break

        signer = ECPV(private_key=priv, curve='brainpoolP384r1')
        verifier = ECPV(public_key=pub, curve='brainpoolP384r1')

        if not signer._public_key_digest == verifier._public_key_digest:
            print "PSK FAIL"
            break

        if not verifier.decrypt(signer.encrypt(msg, 0), 0) == msg:
            print "DEC FAIL"
            break

        msg3 = verifier.decode(signer.encode(msg, 0), 0)
        if not msg == msg3:
            print "VRFY2 FAIL: ", msg3
            break

        msg41 = msg + '1234'
        msg4 = verifier.unpack(signer.pack(msg41))
        if not msg41 == msg4:
            print "VRFY3 FAIL: ", msg4
            break

        req = verifier.generate_kex_request()
        resp, key = signer.process_kex_request(req, 0)
        key2 = verifier.process_kex_response(resp, 0)
        if not list(key) == list(reversed(key2)):
            print "KEX FAILED", key, key2
            break
