# -*- coding: utf-8 -*-

__all__ = [
    'getLogger', 'PupyCmdLoop', 'PupyService',
    'PupyConfig', 'PupyServer', 'PupyModule',
    'Credentials', 'PupyClient',
    'ROOT', 'PUPYLIB_DIR',
    'HOST_SYSTEM', 'HOST_CPU_ARCH', 'HOST_OS_ARCH'
]

import os
import sys
import platform
import re

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
PUPYLIB_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__)))
HOST_SYSTEM = platform.system()
HOST_CPU_ARCH = platform.architecture()[0]
HOST_OS_ARCH = platform.machine()

USE_PIPX = False
# hotpatch for pipx installs. TODO: do this a cleaner way
if "/pipx/venv" in ROOT:
    res = re.findall("(.*/pipx/venvs/[^/]+)", ROOT)
    if len(res) == 1:
        ROOT = os.path.join(res[0], "data", "pupy")
        USE_PIPX = True

DEPS = [
        os.path.abspath(os.path.join(ROOT, 'library_patches_py3')),
        os.path.abspath(os.path.join(ROOT, 'packages', 'all')),
        ]

for dep in DEPS:
    if not os.path.exists(dep):
        raise Exception("Dependency path not found : {}".format(dep))
    if "library_patches" in dep:
        sys.path.insert(0, dep)
    else:
        sys.path.append(dep)

# dirty, TODO: refactor PupyCompiler to be able to call it standalone
if not getattr(sys, '__from_build_library_zip_compiler__', False):
    from .PupyLogger import getLogger

    from .PupyConfig import PupyConfig
    from .PupyCredentials import Credentials

    from pupy.network.conf import load_network_modules

    load_network_modules()

    if not getattr(sys, '__pupy_main__', False):
        from .PupyCmd import PupyCmdLoop
        from .PupyService import PupyService
        from .PupyModule import PupyModule
        from .PupyClient import PupyClient
        from .PupyServer import PupyServer

