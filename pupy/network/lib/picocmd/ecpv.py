# -*- coding: utf-8 -*-

from tinyec import ec, registry
import os
import math
import struct
import base64

from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Hash import SHA1, SHA3_256, SHA3_512

class ECPV(object):
    __slots__ = (
        '_curve', '_bytes', '_bits', '_hash',
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

        self._curve = registry.get_curve(curve)
        self._bytes = (int(math.log(self._curve.field.p, 2)) + 7) / 8
        self._bits = self._bytes * 8
        self._hash = hash

        # Check that hash is properly initialized
        self._hash.new()

        try:
            self._mgf_size = self._hash.new().block_size
        except AttributeError:
            self._mgf_size = self._hash.digest_size

        if not self._mgf_size >= self._bytes:
            raise ValueError('Incompatible hash function')

        if private_key:
            self._private_key = self._from_bytes(base64.decodestring(private_key))
        else:
            self._private_key = None

        if private_key and not public_key:
            self._public_key = self._curve.g * self._private_key
        elif public_key:
            self._public_key = self._osp2ec(base64.decodestring(public_key))
        else:
            self._public_key = None

        self._kex_shared_key = None
        self._kex_public_key = None
        self._kex_private_key = None

        if self._public_key:
            self._public_key_digest = self._mgf2(self._ec2osp(self._public_key), AES.block_size)
        else:
            self._public_key_digest = None

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
        clone._bytes = self._bytes
        clone._bits = self._bits
        clone._hash = self._hash
        clone._private_key = self._private_key
        clone._public_key = self._public_key
        clone._public_key_digest = self._public_key_digest
        clone._kex_shared_key = None
        clone._kex_public_key = None
        clone._kex_private_key = None
        return clone

    def lg(self, a, p):
        ls = pow(a, (p - 1)/2, p)
        if ls == p - 1:
            return -1
        return ls


    def sqrtp(self, a, p):
        a %= p
        if a == 0:
            return [0]

        if p == 2:
            return [a]

        if self.lg(a, p) != 1:
            return []

        if p % 4 == 3:
            x = pow(a, (p + 1)>>2, p)
            return [x, p-x]

        q, s = p - 1, 0
        while q & 1 == 0:
            s += 1
            q >>= 1
        z = 1
        while self.lg(z, p) != -1:
            z += 1
        c = pow(z, q, p)

        x = pow(a, (q + 1)>>1, p)
        t = pow(a, q, p)
        m = s
        while t != 1:
            i, e = 0, 2
            for i in xrange(1, m):
                if pow(t, e, p) == 1:
                    break
                e *= 2

            b = pow(c, 1 << (m - i - 1), p)
            x = (x * b) % p
            t = (t * b * b) % p
            c = (b * b) % p
            m = i

        return [x, p-x]

    def _ec2osp(self, point):
        x = point.x
        y = point.y & 1
        compressed = y << self._bits | x
        return self._to_bytes(compressed)

    def _osp2ec(self, bytes):
        compressed = self._from_bytes(bytes)
        y = compressed >> self._bits
        x = compressed & (1 << self._bits) - 1
        if x == 0:
            y = self._curve.b
        else:
            result = self.sqrtp(x ** 3 + self._curve.a * x + self._curve.b, self._curve.field.p)
            if len(result) == 1:
                y = result[0]
            elif len(result) == 2:
                y1, y2 = result
                y = y1 if (y1 & 1 == y) else y2
            else:
                return None

        return ec.Point(self._curve, x, y)


    def _from_bytes(self, bytes):
        return sum(ord(byte) * (256**i) for i, byte in enumerate(bytes))


    def _to_bytes(self, value):
        bytes = []
        while value:
            bytes.append(chr(value % 256))
            value = value >> 8
        return ''.join(bytes)


    def _gen_random(self):
        value = None
        while not value > 1 and value < self._curve.field.n:
            value = self._from_bytes(os.urandom(self._bytes))
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
        self._public_key_digest = self._mgf2(self._ec2osp(self._public_key), AES.block_size)

        return (
            base64.b64encode(self._to_bytes(self._private_key)),
            base64.b64encode(self._ec2osp(self._public_key))
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
            key = self._mgf2(self._ec2osp(R), 16)

            r = self.encrypt(message, nonce, key=key)

            hash = self._hash.new()
            hash.update(r + (
                struct.pack('>I', nonce) if nonce else b''
            ) + struct.pack('>I', len(r)))
            u = hash.digest()[:self._bytes]
            t = self._from_bytes(u)
            if not (t > 1 and t < self._curve.field.n):
                continue

            s = (k - self._private_key * t) % self._curve.field.n

        bytes = self._to_bytes(s)
        if len(bytes) != self._bytes:
            bytes = bytes + '\x00' * (self._bytes - len(bytes))

        return bytes + r


    def unpack(self, message, nonce=None):
        if not self._public_key:
            raise ValueError('No public key')
        s = self._from_bytes(message[:self._bytes])
        r = message[self._bytes:]
        hash = self._hash.new()
        hash.update(r + (
            struct.pack('>I', nonce) if nonce else b''
        ) + struct.pack('>I', len(r)))
        u = hash.digest()[:self._bytes]
        t = self._from_bytes(u)
        if not (t >= 0 and t < self._curve.field.n):
            return None
        R = self._curve.g * s + self._public_key * t
        if R == ec.Inf(self._curve):
            return None
        key = self._mgf2(self._ec2osp(R), 16)

        return self.decrypt(r, nonce, key=key)


    def generate_kex_request(self):
        self._kex_private_key = self._gen_random()
        self._kex_public_key = self._curve.g * self._kex_private_key
        return self._ec2osp(self._kex_public_key)


    def process_kex_request(self, request, nonce=None, encrypt=False, key_size=AES.block_size):
        if request == self._cached_kex_request and self._kex_shared_key:
            return self._cached_kex_response, self._kex_shared_key

        self._cached_kex_request = request
        response = self.generate_kex_request()
        self.process_kex_response(request, nonce=nonce, decrypt=False, key_size=key_size)
        self._kex_shared_key = list(x for x in reversed(self._kex_shared_key))
        self._cached_kex_response = \
          self.pack(response, nonce) if encrypt else response
        return self._cached_kex_response, self._kex_shared_key


    def process_kex_response(self, response, nonce=None, decrypt=False, key_size=AES.block_size):
        if decrypt:
            response = self.unpack(response, nonce)
        P1 = self._osp2ec(response)
        key = self._mgf2(self._ec2osp(P1 * self._kex_private_key), key_size)
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
        h.update(self._to_bytes(len(message)))
        h.update(self._to_bytes(nonce))

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
        h.update(self._to_bytes(len(message)))
        h.update(self._to_bytes(nonce))

        csum = h.digest()[:4]
        return csum

    def encrypt(self, message, nonce, key=None):
        if not key:
            if self._kex_shared_key:
                key = self._kex_shared_key[0]
            else:
                key = self._public_key_digest

        if nonce is not None:
            counter = Counter.new(
                nbits=AES.block_size*8,
                initial_value=nonce
            )
            encrypted = AES.new(
                key, AES.MODE_CTR, counter=counter
            ).encrypt(message)
        else:
            bs = AES.block_size
            iv = os.urandom(AES.block_size)
            length = struct.pack('>I', len(message))
            pad = (bs - (len(message) + len(length))%bs) % bs
            padding = struct.pack('B', pad)*pad
            encrypted = iv + AES.new(
                key, AES.MODE_CFB, IV=iv
            ).encrypt(length + message + padding)

        return encrypted


    def decrypt(self, message, nonce, key=None):
        if not key:
            if self._kex_shared_key:
                key = self._kex_shared_key[1]
            else:
                key = self._public_key_digest

        if nonce is not None:
            counter = Counter.new(
                nbits=AES.block_size*8,
                initial_value=nonce
            )
            decrypted = AES.new(
                key, AES.MODE_CTR, counter=counter
            ).decrypt(message)
        else:
            bs = AES.block_size
            iv, body = message[:bs], message[bs:]

            payload = AES.new(
                key, AES.MODE_CFB, IV=iv
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


if __name__ == '__main__':
    import hashlib

    for x in xrange(1, 10):
        x = ECPV(curve='brainpoolP384r1', hash=hashlib.sha384)
        priv, pub = x.generate_key()
        print "PRIV:", priv
        print "PUB:", pub
        msg = 'Hello, world'
        msg2 = x.decode(x.encode(msg, 0), 0)
        if not msg == msg2:
            print "VRFY1 FAIL: ", msg2
            break

        signer = ECPV(private_key=priv, curve='brainpoolP384r1', hash=hashlib.sha384)
        verifier = ECPV(public_key=pub, curve='brainpoolP384r1', hash=hashlib.sha384)

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
