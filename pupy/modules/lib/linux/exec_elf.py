#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import zlib
import threading

def mexec(module, path, argv, argv0=None, interactive=False):
    data = zlib.compress(open(path).read())

    module.mp = module.client.conn.modules.memexec.MExec(
        data, argv0, args = argv,
        no_stdin = not interactive,
        no_stdor = False,
        compressed = True
    )

    module.mp.run()

    completed = threading.Event()

    if interactive:
        def on_read(data, error=False):
            module.log(data)

        def on_exit():
            completed.set()

        stdin = module.mp.get_shell(on_read, on_exit)

        while not completed.is_set():
            data = raw_input()
            stdin.write(data+'\n')

    else:
        log = module.mp.get_stdout()
        module.log(log)
        return log
