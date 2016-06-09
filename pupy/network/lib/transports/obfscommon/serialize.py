"""Helper functions to go from integers to binary data and back."""

import struct

def htonl(n):
    """
    Convert integer in 'n' from host-byte order to network-byte order.
    """
    return struct.pack('!I', n)

def ntohl(bs):
    """
    Convert integer in 'n' from network-byte order to host-byte order.
    """
    return struct.unpack('!I', bs)[0]

def htons(n):
    """
    Convert integer in 'n' from host-byte order to network-byte order.
    """
    return struct.pack('!h', n)

def ntohs(bs):
    """
    Convert integer in 'n' from network-byte order to host-byte order.
    """
    return struct.unpack('!h', bs)[0]
