# -*- coding: utf-8 -*-
# --------------------------------------------------------------
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE
# --------------------------------------------------------------

import sys
from contextlib import contextmanager
from rpyc.utils.helpers import restricted
import textwrap
import json
import zlib

def safe_obtain(proxy):
    """ safe version of rpyc's rpyc.utils.classic.obtain, without using pickle. """

    if type(proxy) in [list, str, bytes, dict, set, type(None)]:
        return proxy

    conn = object.__getattribute__(proxy, "____conn__")()
    data = conn.root.json_dumps(proxy, compressed=True)
    data = zlib.decompress(data)

    try:
        data = data.decode('utf-8')
    except:
        data = data.decode('latin1')

    data = json.loads(data) # should prevent any code execution

    return data

def obtain(proxy):
    return safe_obtain(proxy)

def hotpatch_oswrite(conn):
    """ some scripts/libraries use os.write(1, ...) instead of sys.stdout.write to write to stdout """
    conn.execute(textwrap.dedent("""
    import sys
    import os
    if not hasattr(os, 'real_write'):
        setattr(os, 'real_write', os.write)
        def patched_write(fd, s):
            if fd==1:
                return sys.stdout.write(s)
            elif fd==2:
                return sys.stdout.write(s)
            else:
                return os.real_write(fd, s)
        os.write=patched_write
    """))

@contextmanager
def redirected_stdo(module, stdout=None, stderr=None):
    conn = module.client.conn
    if stdout is None:
        stdout = module.stdout
    if stderr is None:
        stderr = module.stdout

    hotpatch_oswrite(conn)
    orig_stdout = conn.modules.sys.stdout
    orig_stderr = conn.modules.sys.stderr
    try:
        conn.modules.sys.stdout = restricted(stdout,["softspace", "write", "flush"])
        conn.modules.sys.stderr = restricted(stderr,["softspace", "write", "flush"])
        yield
    finally:
        conn.modules.sys.stdout = orig_stdout
        conn.modules.sys.stderr = orig_stderr

def interact(module):
    """remote interactive interpreter

    :param conn: the RPyC connection
    :param namespace: the namespace to use (a ``dict``)
    """
    with redirected_stdio(module):
        conn.execute("""def _rinteract():
            def new_exit():
                print "use ctrl+D to exit the interactive python interpreter."
            import code
            code.interact(local = dict({"exit":new_exit, "quit":new_exit}))""")
        conn.namespace["_rinteract"]()

@contextmanager
def redirected_stdio(module, stdout=None, stderr=None):
    r"""
    Redirects the other party's ``stdin``, ``stdout`` and ``stderr`` to
    those of the local party, so remote IO will occur locally.

    Example usage::

        with redirected_stdio(conn):
            conn.modules.sys.stdout.write("hello\n")   # will be printed locally

    """
    conn = module.client.conn
    orig_stdin = conn.modules.sys.stdin
    orig_stdout = conn.modules.sys.stdout
    orig_stderr = conn.modules.sys.stderr

    if stdout is None:
        stdout = module.stdout
    if stderr is None:
        stderr = module.stdout

    try:
        conn.modules.sys.stdin = restricted(sys.stdin, ["softspace", "write", "readline", "encoding", "close"])
        conn.modules.sys.stdout = restricted(stdout, ["softspace", "write", "readline", "encoding", "close", "flush"])
        conn.modules.sys.stderr = restricted(stderr, ["softspace", "write", "readline", "encoding", "close", "flush"])
        yield
    finally:
        conn.modules.sys.stdin = orig_stdin
        conn.modules.sys.stdout = orig_stdout
        conn.modules.sys.stderr = orig_stderr
