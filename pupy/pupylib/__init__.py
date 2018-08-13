# -*- coding: utf-8 -*-

__all__ = [
    'getLogger', 'PupyCmdLoop', 'PupyService',
    'PupyConfig', 'PupyServer', 'PupyModule',
    'Credentials', 'PupyClient',
    'ROOT',
    'HOST_SYSTEM', 'HOST_CPU_ARCH', 'HOST_OS_ARCH'
]

import os
import platform

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
HOST_SYSTEM = platform.system()
HOST_CPU_ARCH = platform.architecture()[0]
HOST_OS_ARCH = platform.machine()

from PupyLogger import getLogger

from PupyCmd import PupyCmdLoop
from PupyConfig import PupyConfig
from PupyService import PupyService
from PupyModule import PupyModule
from PupyCredentials import Credentials
from PupyClient import PupyClient
from PupyServer import PupyServer
