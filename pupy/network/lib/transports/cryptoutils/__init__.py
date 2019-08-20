# -*- encoding: utf-8 -*-

__all__ = (
    'append_PKCS7_padding', 'strip_PKCS7_padding',
    'NewAESCipher', 'get_random',
    'SHA1', 'SHA256', 'SHA384', 'SHA3_256', 'SHA3_512',
    'AES_MODE_CTR', 'AES_MODE_CFB', 'AES_MODE_CBC',
    'hmac_sha256_digest', 'AES_BLOCK_SIZE', 'RC4', 'ECPV'
)

from .aes import (
    append_PKCS7_padding,
    strip_PKCS7_padding,
    NewAESCipher, AES_BLOCK_SIZE,
    AES_MODE_CTR, AES_MODE_CFB, AES_MODE_CBC
)

from .sha import (
    SHA1, SHA256, SHA384, SHA3_256, SHA3_512
)

try:
    from Crypto.Random import get_random_bytes as get_random
    from Crypto.Cipher import ARC4
    from Crypto.Hash import HMAC

    def RC4(key):
        return ARC4.new(key)

    def hmac_sha256_digest(key, msg):
        return HMAC.new(key, msg, SHA256).digest()

except ImportError as e:
    import hashlib
    import hmac

    from os import urandom as get_random
    from .rc4 import RC4

    def hmac_sha256_digest(key, msg):
        return hmac.new(key, msg, hashlib.sha256).digest()

from .ecpv import ECPV
