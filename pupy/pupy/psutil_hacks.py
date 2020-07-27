# -*- coding: utf-8 -*-

from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import sys


if sys.platform == 'win32' and sys.version_info.major < 3:
    def apply_psutil_hacks():
        try:
            import psutil
        except ImportError:
            return

        psutil._pswindows.py2_strencode = lambda x: x

else:
    def apply_psutil_hacks():
        pass
