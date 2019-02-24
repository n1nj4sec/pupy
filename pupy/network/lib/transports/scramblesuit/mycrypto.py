"""
This module provides cryptographic functions not implemented in PyCrypto.

The implemented algorithms include HKDF-SHA256, HMAC-SHA256-128, (CS)PRNGs and
an interface for encryption and decryption using AES in counter mode.
"""

from ... import base
from ..cryptoutils import (
    hmac_sha256_digest, AES_MODE_CTR, NewAESCipher
)

from struct import unpack

import const
import logging

from math import ceil

log = logging


class HKDF_SHA256(object):

    """
    Implements HKDF using SHA256: https://tools.ietf.org/html/rfc5869

    This class only implements the `expand' but not the `extract' stage since
    the provided PRK already exhibits strong entropy.
    """

    __slots__ = (
        'hashLen', 'N', 'prk', 'info',
        'length', 'ctr', 'T'
    )

    def __init__(self, prk, info="", length=32):
        """
        Initialise a HKDF_SHA256 object.
        """

        self.hashLen = const.SHA256_LENGTH

        if length > (self.hashLen * 255):
            raise ValueError("The OKM's length cannot be larger than %d." %
                             (self.hashLen * 255))

        if len(prk) < self.hashLen:
            raise ValueError("The PRK must be at least %d bytes in length "
                             "(%d given)." % (self.hashLen, len(prk)))

        self.N = ceil(float(length) / self.hashLen)
        self.prk = prk
        self.info = info
        self.length = length
        self.ctr = 1
        self.T = ""

    def expand(self):
        """
        Return the expanded output key material.

        The output key material is calculated based on the given PRK, info and
        L.
        """

        # Prevent the accidental re-use of output keying material.
        if len(self.T) > 0:
            raise base.PluggableTransportError("HKDF-SHA256 OKM must not "
                                               "be re-used by application.")

        tmp = ''

        while self.length > len(self.T):
            tmp = hmac_sha256_digest(self.prk, tmp + self.info + chr(self.ctr))
            self.T += tmp
            self.ctr += 1

        return self.T[:self.length]


def HMAC_SHA256_128(key, msg):
    """
    Return the HMAC-SHA256-128 of the given `msg' authenticated by `key'.
    """

    assert(len(key) >= const.SHARED_SECRET_LENGTH)

    h = hmac_sha256_digest(key, msg)

    # Return HMAC truncated to 128 out of 256 bits.
    return h[:16]


class PayloadCrypter(object):

    """
    Provides methods to encrypt data using AES in counter mode.

    This class provides methods to set a session key as well as an
    initialisation vector and to encrypt and decrypt data.
    """

    __slots__ = ('sessionKey', 'crypter')

    def __init__(self):
        """
        Initialise a PayloadCrypter object.
        """

        log.debug("Initialising AES-CTR instance.")

        self.sessionKey = None
        self.crypter = None

    def setSessionKey(self, key, iv):
        """
        Set AES' session key and the initialisation vector for counter mode.

        The given `key' and `iv' are used as 256-bit AES key and as 128-bit
        initialisation vector for counter mode.  Both, the key as well as the
        IV must come from a CSPRNG.
        """

        self.sessionKey = key

        # Our 128-bit counter has the following format:
        # [ 64-bit static and random IV ] [ 64-bit incrementing counter ]
        # Counter wrapping is not allowed which makes it possible to transfer
        # 2^64 * 16 bytes of data while avoiding counter reuse.  That amount is
        # effectively out of reach given today's networking performance.
        log.debug("Setting IV for AES-CTR.")

        iv = (unpack('>Q', iv)[0] << 64) + 1

        self.crypter = NewAESCipher(key, iv, AES_MODE_CTR)

    def encrypt(self, data):
        """
        Encrypts the given `data' using AES in counter mode.
        """

        return self.crypter.encrypt(data)

    # Encryption equals decryption in AES-CTR.
    decrypt = encrypt
