#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import zlib

from pupylib.utils.rpyc_utils import redirected_stdio

def mexec(module, path, argv, argv0=None, interactive=False):
    data = zlib.compress(open(path).read())

    module.mp = module.client.conn.modules.memexec.MExec(
        data, argv0, args = argv,
        no_stdin = not interactive,
        no_stdor = False,
        compressed = True
    )

    with redirected_stdio(module.client.conn):
        module.mp.run()
        if interactive:
            module.mp.get_shell()
        else:
            log = module.mp.get_stdout()
            module.log(log)
            return log
