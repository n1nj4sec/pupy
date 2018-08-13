#!/usr/bin/env python
# -*- coding: utf-8 -*-

import zlib
import threading

from modules.lib.utils.cmdrepl import CmdRepl

def mexec(module, path, argv, argv0=None, interactive=False, raw=False, codepage=None):
    data = zlib.compress(path if raw else open(path).read())

    MExec = module.client.remote('memexec', 'MExec', False)

    module.mp = MExec(
        data, argv0, args = argv,
        no_stdin = not interactive,
        no_stdor = not interactive,
        redirect_stdio = interactive,
        compressed = True,
        terminate = interactive
    )

    complete = threading.Event()

    if interactive:
        repl, _ = CmdRepl.thread(
            module.stdout,
            module.mp.write,
            complete,
            False, None,
            codepage
        )

        module.client.conn.register_remote_cleanup(
            module.mp.close
        )

        if module.mp.execute(complete.set, repl._con_write):
            complete.wait()
            module.mp.close()

            module.client.conn.unregister_remote_cleanup(
                module.mp.close
            )

            module.success('Process exited. Press ENTER')
        else:
            complete.set()
            module.error('Launch failed. Press ENTER')

    else:
        if module.mp.run():
            module.success('Process started: {}'.format(module.mp.pid))
        else:
            module.error('Launch failed')
