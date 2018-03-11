#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
The obfs3 module implements the obfs3 protocol.
"""

__all__ = ( 'Obfs3Client', 'Obfs3Server' )

import random

from ..obfscommon import aes
from . import obfs3_dh
from ...base import BaseTransport
from ..obfscommon import hmac_sha256
from ..obfscommon import rand

#from twisted.internet import threads
from ..obfscommon import threads

import logging

logger = logging.getLogger('obfs3')

MAX_PADDING = 8194

PUBKEY_LEN = 192
KEYLEN = 16  # is the length of the key used by E(K,s) -- that is, 16.
HASHLEN = 32 # length of output of sha256

ST_WAIT_FOR_KEY = 0 # Waiting for public key from the other party
ST_WAIT_FOR_HANDSHAKE = 1 # Waiting for the DH handshake
ST_SEARCHING_MAGIC = 2 # Waiting for magic strings from the other party
ST_OPEN = 3 # obfs3 handshake is complete. Sending application data.

class Obfs3Transport(BaseTransport):
    """
    Obfs3Transport implements the obfs3 protocol.
    """

    __slots__ = (
        'state',  'dh', 'shared_secret', 'scanned_padding',
        'last_padding_chunk', 'other_magic_value',
        'send_crypto', 'recv_crypto', 'queued_data',
        'send_keytype', 'recv_keytype', 'send_magic_const',
        'recv_magic_const', 'we_are_initiator'
    )

    def __init__(self, *args, **kwargs):
        """Initialize the obfs3 pluggable transport."""
        super(Obfs3Transport, self).__init__(*args, **kwargs)

        # Our state.
        self.state = ST_WAIT_FOR_KEY

        # Uniform-DH object
        self.dh = obfs3_dh.UniformDH()

        # DH shared secret
        self.shared_secret = None

        # Bytes of padding scanned so far.
        self.scanned_padding = 0
        # Last padding bytes scanned.
        self.last_padding_chunk = ''

        # Magic value that the other party is going to send
        # (initialized after deriving shared secret)
        self.other_magic_value = None
        # Crypto to encrypt outgoing data.
        self.send_crypto = None
        # Crypto to decrypt incoming data.
        self.recv_crypto = None

        # Buffer for the first data, Tor is trying to send but can't right now
        # because we have to handle the DH handshake first.
        self.queued_data = ''

        # Attributes below are filled by classes that inherit Obfs3Transport.
        self.send_keytype = None
        self.recv_keytype = None
        self.send_magic_const = None
        self.recv_magic_const = None
        self.we_are_initiator = None

    def circuitConnected(self):
        """
        Do the obfs3 handshake:
        PUBKEY | WR(PADLEN)
        """
        padding_length = random.randint(0, MAX_PADDING/2)

        public_key = self.dh.get_public()

        handshake_message = public_key + rand.random_bytes(padding_length)

        if __debug__:
            logger.debug(
                "obfs3 handshake: %s queued %d bytes (padding_length: %d) (public key: %s).",
                "initiator" if self.we_are_initiator else "responder",
                len(handshake_message), padding_length, repr(public_key))

        self.circuit.downstream.write(handshake_message)

    def receivedUpstream(self, data):
        """
        Got data from upstream. We need to obfuscated and proxy them downstream.
        """
        if not self.send_crypto:
            if __debug__:
                logger.debug("Got upstream data before doing handshake. Caching.")

            self.queued_data += data.read()
            return

        message = self.send_crypto.crypt(data.read())

        if __debug__:
            logger.debug("obfs3 receivedUpstream: Transmitting %d bytes.", len(message))

        # Proxy encrypted message.
        self.circuit.downstream.write(message)

    def receivedDownstream(self, data):
        """
        Got data from downstream. We need to de-obfuscate them and
        proxy them upstream.
        """

        if self.state == ST_WAIT_FOR_KEY: # Looking for the other peer's pubkey
            if __debug__:
                logger.debug("Wait for key")

            self._read_handshake(data)

        if self.state == ST_WAIT_FOR_HANDSHAKE: # Doing the exp mod
            if __debug__:
                logger.debug("Wait for handshake")

            return

        if self.state == ST_SEARCHING_MAGIC: # Looking for the magic string
            if __debug__:
                logger.debug("Search magic")

            self._scan_for_magic(data)

        if self.state == ST_OPEN: # Handshake is done. Just decrypt and read application data.
            if __debug__:
                logger.debug("obfs3 receivedDownstream: Processing %d bytes of application data." %
                        (len(data)))

            if len(data) == 0:
                return

            self.circuit.upstream.write(self.recv_crypto.crypt(data.read()))

    def _read_handshake(self, data):
        """
        Read handshake message, parse the other peer's public key and
        schedule the key exchange for execution outside of the event loop.
        """

        if len(data) < PUBKEY_LEN:
            if __debug__:
                logger.debug("Read handshake - short read")

            return

        # Get the public key from the handshake message, do the DH and
        # get the shared secret.
        other_pubkey = data.read(PUBKEY_LEN)

        if __debug__:
            logger.debug("Other pubkey: {}".format(repr(other_pubkey)))

        self.state = ST_WAIT_FOR_HANDSHAKE

        try:
            kex = self.dh.get_secret(other_pubkey)
            self._read_handshake_post_dh(kex, data)
        except Exception, e:
            if __debug__:
                logger.debug('DH Exception: {}'.format(e))

            self._uniform_dh_errback(e, other_pubkey)

    def _uniform_dh_errback(self, failure, other_pubkey):
        """
        Worker routine that does the actual UniformDH key exchange.  We need to
        call it from a defered so that it does not block the main event loop.
        """

        self.circuit.close()
        #e = failure.trap(ValueError)
        if __debug__:
            logger.warning("obfs3: Corrupted public key '%s'" % repr(other_pubkey))

    def _read_handshake_post_dh(self, shared_secret, data):
        """
        Setup the crypto from the calculated shared secret, and complete the
        obfs3 handshake.
        """

        if __debug__:
            logger.debug('DH Complete, secret: {}'.format(repr(shared_secret)))

        self.shared_secret = shared_secret

        # Set up our crypto.
        self.send_crypto = self._derive_crypto(self.send_keytype)
        self.recv_crypto = self._derive_crypto(self.recv_keytype)
        self.other_magic_value = hmac_sha256.hmac_sha256_digest(self.shared_secret,
                                                                self.recv_magic_const)

        # Send our magic value to the remote end and append the queued outgoing data.
        # Padding is prepended so that the server does not just send the 32-byte magic
        # in a single TCP segment.
        padding_length = random.randint(0, MAX_PADDING/2)
        if __debug__:
            logger.debug('Padding length: {}'.format(padding_length))

        magic = hmac_sha256.hmac_sha256_digest(self.shared_secret, self.send_magic_const)
        message = rand.random_bytes(padding_length) + magic + self.send_crypto.crypt(self.queued_data)
        self.queued_data = ''

        self.state = ST_SEARCHING_MAGIC

        if __debug__:
            logger.debug('Scan for magic data / remain data: {}'.format(len(data)))

        if len(data) > 0:
             self._scan_for_magic(data)

        self.circuit.downstream.write(message)

    def _scan_for_magic(self, data):
        """
        Scan 'data' for the magic string. If found, drain it and all
        the padding before it. Then open the connection.
        """

        assert(self.other_magic_value)
        chunk = data.peek()

        index = chunk.find(self.other_magic_value)
        if index < 0:
            if __debug__:
                logger.debug('Magic not found / chunk len: {}'.format(len(chunk)))

            if (len(data) > MAX_PADDING+HASHLEN):
                raise Exception("obfs3: Too much padding (%d)!" % len(data))
            return

        if __debug__:
            logger.debug('Magic (len={}) found at: {}'.format(
                index, len(self.other_magic_value)))

        index += len(self.other_magic_value)
        data.drain(index)

        self.state = ST_OPEN
        if len(data) > 0:
            if __debug__:
                logger.debug('Connection ready, write rest of data: {}'.format(len(data)))

            self.circuit.upstream.write(self.recv_crypto.crypt(data.read()))

    def _derive_crypto(self, pad_string):
        """
        Derive and return an obfs3 key using the pad string in 'pad_string'.
        """
        secret = hmac_sha256.hmac_sha256_digest(self.shared_secret, pad_string)
        return aes.AES_CTR_128(secret[:KEYLEN], secret[KEYLEN:],
                               counter_wraparound=True)

class Obfs3Client(Obfs3Transport):

    """
    Obfs3Client is a client for the obfs3 protocol.
    The client and server differ in terms of their padding strings.
    """

    __slots__ = ()

    def __init__(self, *args, **kwargs):
        Obfs3Transport.__init__(self, *args, **kwargs)

        self.send_keytype = "Initiator obfuscated data"
        self.recv_keytype = "Responder obfuscated data"
        self.send_magic_const = "Initiator magic"
        self.recv_magic_const = "Responder magic"
        self.we_are_initiator = True

class Obfs3Server(Obfs3Transport):

    """
    Obfs3Server is a server for the obfs3 protocol.
    The client and server differ in terms of their padding strings.
    """

    __slots__ = ()

    def __init__(self, *args, **kwargs):
        Obfs3Transport.__init__(self, *args, **kwargs)

        self.send_keytype = "Responder obfuscated data"
        self.recv_keytype = "Initiator obfuscated data"
        self.send_magic_const = "Responder magic"
        self.recv_magic_const = "Initiator magic"
        self.we_are_initiator = False
