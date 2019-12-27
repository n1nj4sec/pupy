# -*- coding: utf-8 -*-
# Glue for backward compatibility

import sys

if 'rpyc' in sys.modules:
    import rpyc

    nowait = getattr(rpyc, 'async')
    brine = rpyc.core.brine

else:
    from network.lib.rpc import nowait
    from network.lib.rpc.core import brine
