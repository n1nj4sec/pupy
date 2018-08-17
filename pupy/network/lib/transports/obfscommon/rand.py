import os

__all__ = ['random_bytes']

def random_bytes(n):
    """ Returns n bytes of strong random data. """

    return os.urandom(n)
