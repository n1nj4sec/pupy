"""Helper functions to go from integers to binary data and back."""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import struct

__all__ = ['htonl', 'ntohl', 'htons', 'ntohs', 'asbyte', 'frombyte']


def htonl(n):
    """
    Convert integer in 'n' from host-byte order to network-byte order.
    """

    return struct.pack('!I', n)

def ntohl(bs):
    """
    Convert integer in 'n' from pupy.network-byte order to host-byte order.
    """
    return struct.unpack('!I', bs)[0]


def htons(n):
    """
    Convert integer in 'n' from host-byte order to network-byte order.
    """
    return struct.pack('!h', n)


def ntohs(bs):
    """
    Convert integer in 'n' from pupy.network-byte order to host-byte order.
    """
    return struct.unpack('!h', bs)[0]


def asbyte(ival):
    return struct.pack('B', ival)


def frombyte(bval):
    return struct.unpack('B', bval)[0]
