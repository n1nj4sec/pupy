"""
This module implements a class to deal with Uniform Diffie-Hellman handshakes.

The class `UniformDH' is used by the server as well as by the client to handle
the Uniform Diffie-Hellman handshake used by ScrambleSuit.
"""

import const
import random
import binascii

import Crypto.Hash.SHA256

import util
import mycrypto

from ..obfs3 import obfs3_dh

import logging
log = logging

class UniformDH( object ):

    """
    Provide methods to deal with Uniform Diffie-Hellman handshakes.

    The class provides methods to extract public keys and to generate public
    keys wrapped in a valid UniformDH handshake.
    """

    def __init__( self, sharedSecret, weAreServer ):
        """
        Initialise a UniformDH object.
        """

        # `True' if we are the server; `False' otherwise.
        self.weAreServer = weAreServer

        # The shared UniformDH secret.
        self.sharedSecret = sharedSecret

        # Cache a UniformDH public key until it's added to the replay table.
        self.remotePublicKey = None

        # Uniform Diffie-Hellman object (implemented in obfs3_dh.py).
        self.udh = None

        # Used by the server so it can simply echo the client's epoch.
        self.echoEpoch = None

    def getRemotePublicKey( self ):
        """
        Return the cached remote UniformDH public key.
        """

        return self.remotePublicKey

    def receivePublicKey( self, data, callback, srvState=None ):
        """
        Extract the public key and invoke a callback with the master secret.

        First, the UniformDH public key is extracted out of `data'.  Then, the
        shared master secret is computed and `callback' is invoked with the
        master secret as argument.  If any of this fails, `False' is returned.
        """

        # Extract the public key sent by the remote host.
        remotePublicKey = self.extractPublicKey(data, srvState)
        if not remotePublicKey:
            return False

        if self.weAreServer:
            self.remotePublicKey = remotePublicKey
            # As server, we need a DH object; as client, we already have one.
            self.udh = obfs3_dh.UniformDH()

        assert self.udh is not None

        try:
            uniformDHSecret = self.udh.get_secret(remotePublicKey)
        except ValueError:
            raise ValueError("Corrupted public key.")

        # First, hash the 4096-bit UniformDH secret to obtain the master key.
        masterKey = Crypto.Hash.SHA256.new(uniformDHSecret).digest()

        # Second, session keys are now derived from the master key.
        callback(masterKey)

        return True

    def extractPublicKey( self, data, srvState=None ):
        """
        Extract and return a UniformDH public key out of `data'.

        Before the public key is touched, the HMAC is verified.  If the HMAC is
        invalid or some other error occurs, `False' is returned.  Otherwise,
        the public key is returned.  The extracted data is finally drained from
        the given `data' object.
        """

        assert self.sharedSecret is not None

        # Do we already have the minimum amount of data?
        if len(data) < (const.PUBLIC_KEY_LENGTH + const.MARK_LENGTH +
                        const.HMAC_SHA256_128_LENGTH):
            return False

        log.debug("Attempting to extract the remote machine's UniformDH "
                  "public key out of %d bytes of data." % len(data))

        handshake = data.peek()

        # First, find the mark to efficiently locate the HMAC.
        publicKey = handshake[:const.PUBLIC_KEY_LENGTH]
        mark = mycrypto.HMAC_SHA256_128(self.sharedSecret, publicKey)

        index = util.locateMark(mark, handshake)
        if not index:
            return False

        # Now that we know where the authenticating HMAC is: verify it.
        hmacStart = index + const.MARK_LENGTH
        existingHMAC = handshake[hmacStart:
                                 (hmacStart + const.HMAC_SHA256_128_LENGTH)]

        authenticated = False
        for epoch in util.expandedEpoch():
            myHMAC = mycrypto.HMAC_SHA256_128(self.sharedSecret,
                                              handshake[0 : hmacStart] + epoch)

            if util.isValidHMAC(myHMAC, existingHMAC, self.sharedSecret):
                self.echoEpoch = epoch
                authenticated = True
                break

            log.debug("HMAC invalid.  Trying next epoch value.")

        if not authenticated:
            log.warning("Could not verify the authentication message's HMAC.")
            return False

        # Do nothing if the ticket is replayed.  Immediately closing the
        # connection would be suspicious.
        if srvState is not None and srvState.isReplayed(existingHMAC):
            log.warning("The HMAC was already present in the replay table.")
            return False

        data.drain(index + const.MARK_LENGTH + const.HMAC_SHA256_128_LENGTH)

        if srvState is not None:
            log.debug("Adding the HMAC authenticating the UniformDH message " \
                      "to the replay table: %s." % existingHMAC.encode('hex'))
            srvState.registerKey(existingHMAC)

        return handshake[:const.PUBLIC_KEY_LENGTH]

    def createHandshake( self, srvState=None ):
        """
        Create and return a ready-to-be-sent UniformDH handshake.

        The returned handshake data includes the public key, pseudo-random
        padding, the mark and the HMAC.  If a UniformDH object has not been
        initialised yet, a new instance is created.
        """

        assert self.sharedSecret is not None

        log.debug("Creating UniformDH handshake message.")

        if self.udh is None:
            self.udh = obfs3_dh.UniformDH()
        publicKey = self.udh.get_public()

        assert (const.MAX_PADDING_LENGTH - const.PUBLIC_KEY_LENGTH) >= 0

        # Subtract the length of the public key to make the handshake on
        # average as long as a redeemed ticket.  That should thwart statistical
        # length-based attacks.
        padding = mycrypto.strongRandom(random.randint(0,
                                        const.MAX_PADDING_LENGTH -
                                        const.PUBLIC_KEY_LENGTH))

        # Add a mark which enables efficient location of the HMAC.
        mark = mycrypto.HMAC_SHA256_128(self.sharedSecret, publicKey)

        if self.echoEpoch is None:
            epoch = util.getEpoch()
        else:
            epoch = self.echoEpoch
            log.debug("Echoing epoch rather than recreating it.")

        # Authenticate the handshake including the current approximate epoch.
        mac = mycrypto.HMAC_SHA256_128(self.sharedSecret,
                                       publicKey + padding + mark + epoch)

        if self.weAreServer and (srvState is not None):
            log.debug("Adding the HMAC authenticating the server's UniformDH "
                      "message to the replay table: %s." % mac.encode('hex'))
            srvState.registerKey(mac)

        return publicKey + padding + mark + mac

# Alias class name in order to provide a more intuitive API.
new = UniformDH
