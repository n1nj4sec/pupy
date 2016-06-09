#!/usr/bin/python
# -*- coding: utf-8 -*-

""" This module is a convenience wrapper for the AES cipher in CTR mode. """

from Crypto.Cipher import AES
from Crypto.Util import Counter

class AES_CTR_128(object):
    """An AES-CTR-128 PyCrypto wrapper."""

    def __init__(self, key, iv, counter_wraparound=False):
        """Initialize AES with the given key and IV.

        If counter_wraparound is set to True, the AES-CTR counter will
        wraparound to 0 when it overflows.
        """

        assert(len(key) == 16)
        assert(len(iv) == 16)

        self.ctr = Counter.new(128, initial_value=long(iv.encode('hex'), 16),
                               allow_wraparound=counter_wraparound)
        self.cipher = AES.new(key, AES.MODE_CTR, counter=self.ctr)

    def crypt(self, data):
        """
        Encrypt or decrypt 'data'.
        """
        return self.cipher.encrypt(data)

