# Original file edited by contact@n1nj4.eu to avoid writing state to disk contact
"""
This module implements several commonly used utility functions.

The implemented functions can be used to swap variables, write and read data
from files and to convert a number to raw text.
"""

import logging
import os
import time
import const

import mycrypto
import StringIO

log = logging

memory_files={}

def setStateLocation( stateLocation ):
    """
    Set the constant `STATE_LOCATION' to the given `stateLocation'.

    The variable `stateLocation' determines where persistent information (such
    as the server's key material) is stored.  If `stateLocation' is `None', it
    remains to be the current directory.  In general, however, it should be a
    subdirectory of Tor's data directory.
    """

    if stateLocation is None:
        return

    if not stateLocation.endswith('/'):
        stateLocation += '/'

    # To be polite, we create a subdirectory inside wherever we are asked to
    # store data in.
    stateLocation += (const.TRANSPORT_NAME).lower() + '/'

    # ...and if it does not exist yet, we attempt to create the full
    # directory path.
    if not os.path.exists(stateLocation):
        log.info("Creating directory path `%s'." % stateLocation)
        os.makedirs(stateLocation)

    log.debug("Setting the state location to `%s'." % stateLocation)
    const.STATE_LOCATION = stateLocation


def isValidHMAC( hmac1, hmac2, key ):
    """
    Compares `hmac1' and `hmac2' after HMACing them again using `key'.

    The arguments `hmac1' and `hmac2' are compared.  If they are equal, `True'
    is returned and otherwise `False'.  To prevent timing attacks, double HMAC
    verification is used meaning that the two arguments are HMACed again before
    (variable-time) string comparison.  The idea is taken from:
    https://www.isecpartners.com/blog/2011/february/double-hmac-verification.aspx
    """

    assert len(hmac1) == len(hmac2)

    # HMAC the arguments again to prevent timing attacks.
    doubleHmac1 = mycrypto.HMAC_SHA256_128(key, hmac1)
    doubleHmac2 = mycrypto.HMAC_SHA256_128(key, hmac2)

    if doubleHmac1 != doubleHmac2:
        return False

    log.debug("The computed HMAC is valid.")

    return True


def locateMark( mark, payload ):
    """
    Locate the given `mark' in `payload' and return its index.

    The `mark' is placed before the HMAC of a ScrambleSuit authentication
    mechanism and makes it possible to efficiently locate the HMAC.  If the
    `mark' could not be found, `None' is returned.
    """

    index = payload.find(mark, 0, const.MAX_PADDING_LENGTH + const.MARK_LENGTH)
    if index < 0:
        log.debug("Could not find the mark just yet.")
        return None

    if (len(payload) - index - const.MARK_LENGTH) < \
       const.HMAC_SHA256_128_LENGTH:
        log.debug("Found the mark but the HMAC is still incomplete.")
        return None

    log.debug("Successfully located the mark.")

    return index


def getEpoch( ):
    """
    Return the Unix epoch divided by a constant as string.

    This function returns a coarse-grained version of the Unix epoch.  The
    seconds passed since the epoch are divided by the constant
    `EPOCH_GRANULARITY'.
    """

    return str(int(time.time()) / const.EPOCH_GRANULARITY)


def expandedEpoch( ):
    """
    Return [epoch, epoch-1, epoch+1].
    """

    epoch = int(getEpoch())

    return [str(epoch), str(epoch - 1), str(epoch + 1)]


def writeToFile( data, fileName ):
    """
    Writes the given `data' to the file specified by `fileName'.

    If an error occurs, the function logs an error message but does not throw
    an exception or return an error code.
    """
    global memory_files
    log.debug("Opening memory file `%s' for writing." % fileName)
    memory_files[fileName]=StringIO.StringIO(data)


def readFromFile( fileName, length=-1 ):
    """
    Read `length' amount of bytes from the given `fileName' 

    If `length' equals -1 (the default), the entire file is read and the
    content returned.  If an error occurs, the function logs an error message
    but does not throw an exception or return an error code.
    """
    global memory_files
    data = None

    if not fileName in memory_files:
        log.debug("Memory File `%s' does not exist (yet?)." % fileName)
        return None

    log.debug("Opening memory file `%s' for reading." % fileName)

    memory_files[fileName].seek(0)
    data = memory_files[fileName].read(length)


    return data


def sanitiseBase32( data ):
    """
    Try to sanitise a Base32 string if it's slightly wrong.

    ScrambleSuit's shared secret might be distributed verbally which could
    cause mistakes.  This function fixes simple mistakes, e.g., when a user
    noted "1" rather than "I".
    """

    data = data.upper()

    if "1" in data:
        log.info("Found a \"1\" in Base32-encoded \"%s\".  Assuming " \
                 "it's actually \"I\"." % data)
        data = data.replace("1", "I")

    if "0" in data:
        log.info("Found a \"0\" in Base32-encoded \"%s\".  Assuming " \
                 "it's actually \"O\"." % data)
        data = data.replace("0", "O")

    return data
