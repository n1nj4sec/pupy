import os

def random_bytes(n):
    """ Returns n bytes of strong random data. """

    return os.urandom(n)

