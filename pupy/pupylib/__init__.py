# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
__all__ = [
    'getLogger', 'PupyCmdLoop', 'PupyService',
    'PupyConfig', 'PupyServer', 'PupyModule',
    'Credentials', 'PupyClient',
    'ROOT',
    'HOST_SYSTEM', 'HOST_CPU_ARCH', 'HOST_OS_ARCH'
]

import os
import sys
import platform

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
HOST_SYSTEM = platform.system()
HOST_CPU_ARCH = platform.architecture()[0]
HOST_OS_ARCH = platform.machine()

from .PupyLogger import getLogger

from .PupyConfig import PupyConfig
from .PupyCredentials import Credentials

from network.conf import load_network_modules

load_network_modules()

if not getattr(sys, '__pupy_main__', False):
    from .PupyCmd import PupyCmdLoop
    from .PupyService import PupyService
    from .PupyModule import PupyModule
    from .PupyClient import PupyClient
    from .PupyServer import PupyServer
