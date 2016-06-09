#!/usr/bin/python
# -*- coding: utf-8 -*-

""" This module contains an implementation of the 'b64' transport. """

from ..base import BaseTransport
import base64
import logging

log = logging

def _get_b64_chunks_from_str(string):
    """
    Given a 'string' of concatenated base64 objects, return a list
    with the objects.

    Assumes that the objects are well-formed base64 strings. Also
    assumes that the padding character of base64 is '='.
    """
    chunks = []

    while True:
        pad_loc = string.find('=')
        if pad_loc < 0 or pad_loc == len(string)-1 or pad_loc == len(string)-2:
            # If there is no padding, or it's the last chunk: append
            # it to chunks and return.
            chunks.append(string)
            return chunks

        if pad_loc != len(string)-1 and string[pad_loc+1] == '=': # double padding
            pad_loc += 1

        # Append the object to the chunks, and prepare the string for
        # the next iteration.
        chunks.append(string[:pad_loc+1])
        string = string[pad_loc+1:]

    return chunks

class B64Transport(BaseTransport):
    """
    Implements the b64 protocol. A protocol that encodes data with
    base64 before pushing them to the network.
    """

    def receivedDownstream(self, data):
        """
        Got data from downstream; relay them upstream.
        """

        decoded_data = ''

        # TCP is a stream protocol: the data we received might contain
        # more than one b64 chunk. We should inspect the data and
        # split it into multiple chunks.
        b64_chunks = _get_b64_chunks_from_str(data.peek())

        # Now b64 decode each chunk and append it to the our decoded
        # data.
        for chunk in b64_chunks:
            try:
                decoded_data += base64.b64decode(chunk)
            except TypeError:
                log.info("We got corrupted b64 ('%s')." % chunk)
                return

        data.drain()
        self.circuit.upstream.write(decoded_data)

    def receivedUpstream(self, data):
        """
        Got data from upstream; relay them downstream.
        """

        self.circuit.downstream.write(base64.b64encode(data.read()))
        return


class B64Client(B64Transport):
    pass


class B64Server(B64Transport):
    pass


