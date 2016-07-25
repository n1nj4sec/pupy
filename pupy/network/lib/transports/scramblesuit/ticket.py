#!/usr/bin/env python

"""
This module provides a session ticket mechanism.

The implemented mechanism is a subset of session tickets as proposed for
TLS in RFC 5077.

The format of a 112-byte ticket is:
 +------------+------------------+--------------+
 | 16-byte IV | 64-byte E(state) | 32-byte HMAC |
 +------------+------------------+--------------+

The 64-byte encrypted state contains:
 +-------------------+--------------------+--------------------+-------------+
 | 4-byte issue date | 18-byte identifier | 32-byte master key | 10-byte pad |
 +-------------------+--------------------+--------------------+-------------+
"""

import os
import time
import const
import yaml
import struct
import random
import datetime

from Crypto.Cipher import AES
from Crypto.Hash import HMAC
from Crypto.Hash import SHA256
#from twisted.internet.address import IPv4Address

import logging

import mycrypto
import util
import state

log = logging


def createTicketMessage( rawTicket, HMACKey ):
    """
    Create and return a ready-to-be-sent ticket authentication message.

    Pseudo-random padding and a mark are added to `rawTicket' and the result is
    then authenticated using `HMACKey' as key for a HMAC.  The resulting
    authentication message is then returned.
    """

    assert len(rawTicket) == const.TICKET_LENGTH
    assert len(HMACKey) == const.TICKET_HMAC_KEY_LENGTH

    # Subtract the length of the ticket to make the handshake on
    # average as long as a UniformDH handshake message.
    padding = mycrypto.strongRandom(random.randint(0,
                                    const.MAX_PADDING_LENGTH -
                                    const.TICKET_LENGTH))

    mark = mycrypto.HMAC_SHA256_128(HMACKey, rawTicket)

    hmac = mycrypto.HMAC_SHA256_128(HMACKey, rawTicket + padding +
                                    mark + util.getEpoch())

    return rawTicket + padding + mark + hmac


def issueTicketAndKey( srvState ):
    """
    Issue a new session ticket and append it to the according master key.

    The parameter `srvState' contains the key material and is passed on to
    `SessionTicket'.  The returned ticket and key are ready to be wrapped into
    a protocol message with the flag FLAG_NEW_TICKET set.
    """

    log.info("Issuing new session ticket and master key.")
    masterKey = mycrypto.strongRandom(const.MASTER_KEY_LENGTH)
    newTicket = (SessionTicket(masterKey, srvState)).issue()

    return masterKey + newTicket


def storeNewTicket( masterKey, ticket, bridge ):
    """
    Store a new session ticket and the according master key for future use.

    This method is only called by clients.  The given data, `masterKey',
    `ticket' and `bridge', is YAMLed and stored in the global ticket
    dictionary.  If there already is a ticket for the given `bridge', it is
    overwritten.
    """

    assert len(masterKey) == const.MASTER_KEY_LENGTH
    assert len(ticket) == const.TICKET_LENGTH

    ticketFile = const.STATE_LOCATION + const.CLIENT_TICKET_FILE

    log.debug("Storing newly received ticket in `%s'." % ticketFile)

    # Add a new (key, ticket) tuple with the given bridge as hash key.
    tickets = dict()
    content = util.readFromFile(ticketFile)
    if (content is not None) and (len(content) > 0):
        tickets = yaml.safe_load(content)

    # We also store a timestamp so we later know if our ticket already expired.
    tickets[str(bridge)] = [int(time.time()), masterKey, ticket]
    util.writeToFile(yaml.dump(tickets), ticketFile)


def findStoredTicket( bridge ):
    """
    Retrieve a previously stored ticket from the ticket dictionary.

    The global ticket dictionary is loaded and the given `bridge' is used to
    look up the ticket and the master key.  If the ticket dictionary does not
    exist (yet) or the ticket data could not be found, `None' is returned.
    """

    assert bridge

    ticketFile = const.STATE_LOCATION + const.CLIENT_TICKET_FILE

    log.debug("Attempting to read master key and ticket from file `%s'." %
              ticketFile)

    # Load the ticket hash table from file.
    yamlBlurb = util.readFromFile(ticketFile)
    if (yamlBlurb is None) or (len(yamlBlurb) == 0):
        return None
    tickets = yaml.safe_load(yamlBlurb)

    try:
        timestamp, masterKey, ticket = tickets[str(bridge)]
    except KeyError:
        log.info("Found no ticket for bridge `%s'." % str(bridge))
        return None

    # We can remove the ticket now since we are about to redeem it.
    log.debug("Deleting ticket since it is about to be redeemed.")
    del tickets[str(bridge)]
    util.writeToFile(yaml.dump(tickets), ticketFile)

    # If our ticket is expired, we can't redeem it.
    ticketAge = int(time.time()) - timestamp
    if ticketAge > const.SESSION_TICKET_LIFETIME:
        log.warning("We did have a ticket but it already expired %s ago." %
                    str(datetime.timedelta(seconds=
                        (ticketAge - const.SESSION_TICKET_LIFETIME))))
        return None

    return (masterKey, ticket)


def checkKeys( srvState ):
    """
    Check whether the key material for session tickets must be rotated.

    The key material (i.e., AES and HMAC keys for session tickets) contained in
    `srvState' is checked if it needs to be rotated.  If so, the old keys are
    stored and new ones are created.
    """

    assert (srvState.hmacKey is not None) and \
           (srvState.aesKey is not None) and \
           (srvState.keyCreation is not None)

    if (int(time.time()) - srvState.keyCreation) > const.KEY_ROTATION_TIME:
        log.info("Rotating server key material for session tickets.")

        # Save expired keys to be able to validate old tickets.
        srvState.oldAesKey = srvState.aesKey
        srvState.oldHmacKey = srvState.hmacKey

        # Create new key material...
        srvState.aesKey = mycrypto.strongRandom(const.TICKET_AES_KEY_LENGTH)
        srvState.hmacKey = mycrypto.strongRandom(const.TICKET_HMAC_KEY_LENGTH)
        srvState.keyCreation = int(time.time())

        # ...and save it to disk.
        srvState.writeState()


def decrypt( ticket, srvState ):
    """
    Decrypts, verifies and returns the given `ticket'.

    The key material used to verify the ticket is contained in `srvState'.
    First, the HMAC over the ticket is verified.  If it is valid, the ticket is
    decrypted.  Finally, a `ProtocolState()' object containing the master key
    and the ticket's issue date is returned.  If any of these steps fail,
    `None' is returned.
    """

    assert (ticket is not None) and (len(ticket) == const.TICKET_LENGTH)
    assert (srvState.hmacKey is not None) and (srvState.aesKey is not None)

    log.debug("Attempting to decrypt and verify ticket.")

    checkKeys(srvState)

    # Verify the ticket's authenticity before decrypting.
    hmac = HMAC.new(srvState.hmacKey, ticket[0:80], digestmod=SHA256).digest()
    if util.isValidHMAC(hmac, ticket[80:const.TICKET_LENGTH],
                        srvState.hmacKey):
        aesKey = srvState.aesKey
    else:
        if srvState.oldHmacKey is None:
            return None

        # Was the HMAC created using the rotated key material?
        oldHmac = HMAC.new(srvState.oldHmacKey, ticket[0:80],
                           digestmod=SHA256).digest()
        if util.isValidHMAC(oldHmac, ticket[80:const.TICKET_LENGTH],
                            srvState.oldHmacKey):
            aesKey = srvState.oldAesKey
        else:
            return None

    # Decrypt the ticket to extract the state information.
    aes = AES.new(aesKey, mode=AES.MODE_CBC,
                  IV=ticket[0:const.TICKET_AES_CBC_IV_LENGTH])
    plainTicket = aes.decrypt(ticket[const.TICKET_AES_CBC_IV_LENGTH:80])

    issueDate = struct.unpack('I', plainTicket[0:4])[0]
    identifier = plainTicket[4:22]
    masterKey = plainTicket[22:54]

    if not (identifier == const.TICKET_IDENTIFIER):
        log.error("The ticket's HMAC is valid but the identifier is invalid.  "
                  "The ticket could be corrupt.")
        return None

    return ProtocolState(masterKey, issueDate=issueDate)


class ProtocolState( object ):

    """
    Defines a ScrambleSuit protocol state contained in a session ticket.

    A protocol state is essentially a master key which can then be used by the
    server to derive session keys.  Besides, a state object contains an issue
    date which specifies the expiry date of a ticket.  This class contains
    methods to check the expiry status of a ticket and to dump it in its raw
    form.
    """

    def __init__( self, masterKey, issueDate=int(time.time()) ):
        """
        The constructor of the `ProtocolState' class.

        The four class variables are initialised.
        """

        self.identifier = const.TICKET_IDENTIFIER
        self.masterKey = masterKey
        self.issueDate = issueDate
        # Pad to multiple of 16 bytes to match AES' block size.
        self.pad = "\0\0\0\0\0\0\0\0\0\0"

    def isValid( self ):
        """
        Verifies the expiry date of the object's issue date.

        If the expiry date is not yet reached and the protocol state is still
        valid, `True' is returned.  If the protocol state has expired, `False'
        is returned.
        """

        assert self.issueDate

        lifetime = int(time.time()) - self.issueDate
        if lifetime > const.SESSION_TICKET_LIFETIME:
            log.debug("The ticket is invalid and expired %s ago." %
                      str(datetime.timedelta(seconds=
                      (lifetime - const.SESSION_TICKET_LIFETIME))))
            return False

        log.debug("The ticket is still valid for %s." %
                  str(datetime.timedelta(seconds=
                  (const.SESSION_TICKET_LIFETIME - lifetime))))
        return True

    def __repr__( self ):
        """
        Return a raw string representation of the object's protocol state.

        The length of the returned representation is exactly 64 bytes; a
        multiple of AES' 16-byte block size.  That makes it suitable to be
        encrypted using AES-CBC.
        """

        return struct.pack('I', self.issueDate) + self.identifier + \
                           self.masterKey + self.pad


class SessionTicket( object ):

    """
    Encrypts and authenticates an encapsulated `ProtocolState()' object.

    This class implements a session ticket which can be redeemed by clients.
    The class contains methods to initialise and issue session tickets.
    """

    def __init__( self, masterKey, srvState ):
        """
        The constructor of the `SessionTicket()' class.

        The class variables are initialised and the validity of the symmetric
        keys for the session tickets is checked.
        """

        assert (masterKey is not None) and \
               len(masterKey) == const.MASTER_KEY_LENGTH

        checkKeys(srvState)

        # Initialisation vector for AES-CBC.
        self.IV = mycrypto.strongRandom(const.TICKET_AES_CBC_IV_LENGTH)

        # The server's (encrypted) protocol state.
        self.state = ProtocolState(masterKey)

        # AES and HMAC keys to encrypt and authenticate the ticket.
        self.symmTicketKey = srvState.aesKey
        self.hmacTicketKey = srvState.hmacKey

    def issue( self ):
        """
        Returns a ready-to-use session ticket after prior initialisation.

        After the `SessionTicket()' class was initialised with a master key,
        this method encrypts and authenticates the protocol state and returns
        the final result which is ready to be sent over the wire.
        """

        self.state.issueDate = int(time.time())

        # Encrypt the protocol state.
        aes = AES.new(self.symmTicketKey, mode=AES.MODE_CBC, IV=self.IV)
        state = repr(self.state)
        assert (len(state) % AES.block_size) == 0
        cryptedState = aes.encrypt(state)

        # Authenticate the encrypted state and the IV.
        hmac = HMAC.new(self.hmacTicketKey,
                        self.IV + cryptedState, digestmod=SHA256).digest()

        finalTicket = self.IV + cryptedState + hmac
        log.debug("Returning %d-byte ticket." % len(finalTicket))

        return finalTicket


# Alias class name in order to provide a more intuitive API.
new = SessionTicket


# Give ScrambleSuit server operators a way to manually issue new session
# tickets for out-of-band distribution.
if __name__ == "__main__":

    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("ip_addr", type=str, help="The IPv4 address of the "
                        "%s server." % const.TRANSPORT_NAME)
    parser.add_argument("tcp_port", type=int, help="The TCP port of the %s "
                        "server." % const.TRANSPORT_NAME)
    parser.add_argument("ticket_file", type=str, help="The file, the newly "
                        "issued ticket is written to.")
    args = parser.parse_args()

    print "[+] Loading server state file."
    serverState = state.load()

    print "[+] Generating new session ticket."
    masterKey = mycrypto.strongRandom(const.MASTER_KEY_LENGTH)
    ticket = SessionTicket(masterKey, serverState).issue()

    print "[+] Writing new session ticket to `%s'." % args.ticket_file
    tickets = dict()
    server = IPv4Address('TCP', args.ip_addr, args.tcp_port)
    tickets[str(server)] = [int(time.time()), masterKey, ticket]

    util.writeToFile(yaml.dump(tickets), args.ticket_file)

    print "[+] Success."
