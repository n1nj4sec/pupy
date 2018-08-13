# -*- coding: utf-8 -*-

__all__ = [
    'PupySocketStream',
]

from PupySocketStream import PupySocketStream

try:
    from PupySocketStream import PupyUDPSocketStream
    __all__.append('PupyUDPSocketStream')

except ImportError:
    PupyUDPSocketStream = None
