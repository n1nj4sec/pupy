"""
This module provides cryptographic functions not implemented in PyCrypto.

The implemented algorithms include HKDF-SHA256, HMAC-SHA256-128, (CS)PRNGs and
an interface for encryption and decryption using AES in counter mode.
"""

import Crypto.Hash.SHA256
import Crypto.Hash.HMAC
import Crypto.Util.Counter
import Crypto.Cipher.AES

from ... import base

import math
import os

import const
import logging
log = logging


class HKDF_SHA256( object ):

    """
    Implements HKDF using SHA256: https://tools.ietf.org/html/rfc5869

    This class only implements the `expand' but not the `extract' stage since
    the provided PRK already exhibits strong entropy.
    """

    def __init__( self, prk, info="", length=32 ):
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

        self.N = math.ceil(float(length) / self.hashLen)
        self.prk = prk
        self.info = info
        self.length = length
        self.ctr = 1
        self.T = ""

    def expand( self ):
        """
        Return the expanded output key material.

        The output key material is calculated based on the given PRK, info and
        L.
        """

        tmp = ""

        # Prevent the accidental re-use of output keying material.
        if len(self.T) > 0:
            raise base.PluggableTransportError("HKDF-SHA256 OKM must not "
                                               "be re-used by application.")

        while self.length > len(self.T):
            tmp = Crypto.Hash.HMAC.new(self.prk, tmp + self.info +
                                       chr(self.ctr),
                                       Crypto.Hash.SHA256).digest()
            self.T += tmp
            self.ctr += 1

        return self.T[:self.length]


def HMAC_SHA256_128( key, msg ):
    """
    Return the HMAC-SHA256-128 of the given `msg' authenticated by `key'.
    """

    assert(len(key) >= const.SHARED_SECRET_LENGTH)

    h = Crypto.Hash.HMAC.new(key, msg, Crypto.Hash.SHA256)

    # Return HMAC truncated to 128 out of 256 bits.
    return h.digest()[:16]


def strongRandom( size ):
    """
    Return `size' bytes of strong randomness suitable for cryptographic use.
    """

    return os.urandom(size)


class PayloadCrypter:

    """
    Provides methods to encrypt data using AES in counter mode.

    This class provides methods to set a session key as well as an
    initialisation vector and to encrypt and decrypt data.
    """

    def __init__( self ):
        """
        Initialise a PayloadCrypter object.
        """

        log.debug("Initialising AES-CTR instance.")

        self.sessionKey = None
        self.crypter = None
        self.counter = None

    def setSessionKey( self, key, iv ):
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
        self.counter = Crypto.Util.Counter.new(64,
                                               prefix = iv,
                                               initial_value = 1,
                                               allow_wraparound = False)

        log.debug("Setting session key for AES-CTR.")
        self.crypter = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CTR,
                                             counter=self.counter)

    def encrypt( self, data ):
        """
        Encrypts the given `data' using AES in counter mode.
        """

        return self.crypter.encrypt(data)

    # Encryption equals decryption in AES-CTR.
    decrypt = encrypt
