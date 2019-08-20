# -*- encoding: utf-8 -*-

__all__ = (
    'SHA1', 'SHA256', 'SHA384', 'SHA3_256', 'SHA3_512'
)

try:
    from Crypto.Hash import SHA1, SHA256, SHA384, SHA3_256, SHA3_512
except ImportError:
    # Not implemented for now
    SHA3_256 = None
    SHA3_512 = None

    from hashlib import sha1, sha256, sha384

    class SHA1(object):
        __slots__ = ()

        @staticmethod
        def new(*args):
            return sha1(*args)

    class SHA256(object):
        __slots__ = ()

        @staticmethod
        def new(*args):
            return sha256(*args)

    class SHA384(object):
        __slots__ = ()

        @staticmethod
        def new(*args):
            return sha384(*args)
