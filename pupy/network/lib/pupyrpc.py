# -*- coding: utf-8 -*-
# Glue for backward compatibility

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

__all__ = ('nowait', 'brine')

import sys

if 'rpyc' in sys.modules:
    import rpyc

    nowait = getattr(rpyc, 'async')
    brine = rpyc.core.brine
    netref = rpyc.core.netref

else:
    from network.lib.rpc import nowait
    from network.lib.rpc.core import brine
