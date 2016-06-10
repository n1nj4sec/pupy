"""
This module provides code to handle ScrambleSuit protocol messages.

The exported classes and functions provide interfaces to handle protocol
messages, check message headers for validity and create protocol messages out
of application data.
"""

from ..obfscommon import serialize as pack
from ... import base
import mycrypto
import const
import logging

log = logging


def createProtocolMessages( data, flags=const.FLAG_PAYLOAD ):
    """
    Create protocol messages out of the given payload.

    The given `data' is turned into a list of protocol messages with the given
    `flags' set.  The list is then returned.  If possible, all messages fill
    the MTU.
    """

    messages = []

    while len(data) > const.MPU:
        messages.append(ProtocolMessage(data[:const.MPU], flags=flags))
        data = data[const.MPU:]

    messages.append(ProtocolMessage(data, flags=flags))

    #log.debug("Created %d protocol messages." % len(messages))

    return messages


def getFlagNames( flags ):
    """
    Return the flag name encoded in the integer `flags' as string.

    This function is only useful for printing easy-to-read flag names in debug
    log messages.
    """

    if flags == 1:
        return "PAYLOAD"

    elif flags == 2:
        return "NEW_TICKET"

    elif flags == 4:
        return "PRNG_SEED"

    else:
        return "Undefined"


def isSane( totalLen, payloadLen, flags ):
    """
    Verifies whether the given header fields are sane.

    The values of the fields `totalLen', `payloadLen' and `flags' are checked
    for their sanity.  If they are in the expected range, `True' is returned.
    If any of these fields has an invalid value, `False' is returned.
    """

    def isFine( length ):
        """
        Check if the given length is fine.
        """

        return True if (0 <= length <= const.MPU) else False

    #log.debug("Message header: totalLen=%d, payloadLen=%d, flags"
    #          "=%s" % (totalLen, payloadLen, getFlagNames(flags)))

    validFlags = [
        const.FLAG_PAYLOAD,
        const.FLAG_NEW_TICKET,
        const.FLAG_PRNG_SEED,
    ]

    return isFine(totalLen) and \
           isFine(payloadLen) and \
           totalLen >= payloadLen and \
           (flags in validFlags)


class ProtocolMessage( object ):

    """
    Represents a ScrambleSuit protocol message.

    This class provides methods to deal with protocol messages.  The methods
    make it possible to add padding as well as to encrypt and authenticate
    protocol messages.
    """

    def __init__( self, payload="", paddingLen=0, flags=const.FLAG_PAYLOAD ):
        """
        Initialises a ProtocolMessage object.
        """

        payloadLen = len(payload)
        if (payloadLen + paddingLen) > const.MPU:
            raise base.PluggableTransportError("No overly long messages.")

        self.totalLen = payloadLen + paddingLen
        self.payloadLen = payloadLen
        self.payload = payload
        self.flags = flags

    def encryptAndHMAC( self, crypter, hmacKey ):
        """
        Encrypt and authenticate this protocol message.

        This protocol message is encrypted using `crypter' and authenticated
        using `hmacKey'.  Finally, the encrypted message prepended by a
        HMAC-SHA256-128 is returned and ready to be sent over the wire.
        """

        encrypted = crypter.encrypt(pack.htons(self.totalLen) +
                                    pack.htons(self.payloadLen) +
                                    chr(self.flags) + self.payload +
                                    (self.totalLen - self.payloadLen) * '\0')

        hmac = mycrypto.HMAC_SHA256_128(hmacKey, encrypted)

        return hmac + encrypted

    def addPadding( self, paddingLen ):
        """
        Add padding to this protocol message.

        Padding is added to this protocol message.  The exact amount is
        specified by `paddingLen'.
        """

        # The padding must not exceed the message size.
        if (self.totalLen + paddingLen) > const.MPU:
            raise base.PluggableTransportError("Can't pad more than the MTU.")

        if paddingLen == 0:
            return

        #log.debug("Adding %d bytes of padding to %d-byte message." %
        #          (paddingLen, const.HDR_LENGTH + self.totalLen))
        self.totalLen += paddingLen

    def __len__( self ):
        """
        Return the length of this protocol message.
        """

        return const.HDR_LENGTH + self.totalLen

# Alias class name in order to provide a more intuitive API.
new = ProtocolMessage

class MessageExtractor( object ):

    """
    Extracts ScrambleSuit protocol messages out of an encrypted stream.
    """

    def __init__( self ):
        """
        Initialise a new MessageExtractor object.
        """

        self.recvBuf = ""
        self.totalLen = None
        self.payloadLen = None
        self.flags = None

    def extract( self, data, aes, hmacKey ):
        """
        Extracts (i.e., decrypts and authenticates) protocol messages.

        The raw `data' coming directly from the wire is decrypted using `aes'
        and authenticated using `hmacKey'.  The payload is then returned as
        unencrypted protocol messages.  In case of invalid headers or HMACs, an
        exception is raised.
        """

        self.recvBuf += data
        msgs = []

        # Keep trying to unpack as long as there is at least a header.
        while len(self.recvBuf) >= const.HDR_LENGTH:

            # If necessary, extract the header fields.
            if self.totalLen == self.payloadLen == self.flags == None:
                self.totalLen = pack.ntohs(aes.decrypt(self.recvBuf[16:18]))
                self.payloadLen = pack.ntohs(aes.decrypt(self.recvBuf[18:20]))
                self.flags = ord(aes.decrypt(self.recvBuf[20]))

                if not isSane(self.totalLen, self.payloadLen, self.flags):
                    raise base.PluggableTransportError("Invalid header.")

            # Parts of the message are still on the wire; waiting.
            if (len(self.recvBuf) - const.HDR_LENGTH) < self.totalLen:
                break

            rcvdHMAC = self.recvBuf[0:const.HMAC_SHA256_128_LENGTH]
            vrfyHMAC = mycrypto.HMAC_SHA256_128(hmacKey,
                              self.recvBuf[const.HMAC_SHA256_128_LENGTH:
                              (self.totalLen + const.HDR_LENGTH)])

            if rcvdHMAC != vrfyHMAC:
                raise base.PluggableTransportError("Invalid message HMAC.")

            # Decrypt the message and remove it from the input buffer.
            extracted = aes.decrypt(self.recvBuf[const.HDR_LENGTH:
                         (self.totalLen + const.HDR_LENGTH)])[:self.payloadLen]
            msgs.append(ProtocolMessage(payload=extracted, flags=self.flags))
            self.recvBuf = self.recvBuf[const.HDR_LENGTH + self.totalLen:]

            # Protocol message processed; now reset length fields.
            self.totalLen = self.payloadLen = self.flags = None

        return msgs
