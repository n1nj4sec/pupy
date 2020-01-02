# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
__all__ = [
    'PupySocketStream',
]

from .PupySocketStream import PupySocketStream

try:
    from .PupySocketStream import PupyUDPSocketStream
    __all__.append('PupyUDPSocketStream')

except ImportError:
    PupyUDPSocketStream = None
