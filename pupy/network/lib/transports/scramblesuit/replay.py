"""
This module implements a mechanism to protect against replay attacks.

The replay protection mechanism is based on a dictionary which caches
previously observed keys.  New keys can be added to the dictionary and existing
ones can be queried.  A pruning mechanism deletes expired keys from the
dictionary.
"""

import time

import const

import logging

log = logging


class Tracker( object ):

    """
    Implement methods to keep track of replayed keys.

    This class provides methods to add new keys (elements), check whether keys
    are already present in the dictionary and to prune the lookup table.
    """

    def __init__( self ):
        """
        Initialise a `Tracker' object.
        """

        self.table = dict()

    def addElement( self, element ):
        """
        Add the given `element' to the lookup table.
        """

        if self.isPresent(element):
            raise LookupError("Element already present in table.")

        # The key is a HMAC and the value is the current Unix timestamp.
        self.table[element] = int(time.time())

    def isPresent( self, element ):
        """
        Check if the given `element' is already present in the lookup table.

        Return `True' if `element' is already in the lookup table and `False'
        otherwise.
        """

        log.debug("Looking for existing element in size-%d lookup table." %
                  len(self.table))

        # Prune the replay table before looking up the given `element'.  This
        # could be done more efficiently, e.g. by pruning every n minutes and
        # only checking the timestamp of this particular element.
        self.prune()

        return (element in self.table)

    def prune( self ):
        """
        Delete expired elements from the lookup table.

        Keys whose Unix timestamps are older than `const.EPOCH_GRANULARITY' are
        being removed from the lookup table.
        """

        log.debug("Pruning the replay table.")

        deleteList = []
        now = int(time.time())

        for element in self.table.iterkeys():
            if (now - self.table[element]) > const.EPOCH_GRANULARITY:
                deleteList.append(element)

        # We can't delete from a dictionary while iterating over it; therefore
        # this construct.
        for elem in deleteList:
            log.debug("Deleting expired element.")
            del self.table[elem]
