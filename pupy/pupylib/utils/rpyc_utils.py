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
import json
import zlib
import msgpack

def safe_obtain(proxy):
    """ safe version of rpyc's rpyc.utils.classic.obtain, without using pickle. """

    try:
        conn = object.__getattribute__(proxy, "____conn__")()
    except AttributeError:
        ptype = type(proxy)

        if type(proxy) in (tuple, list, set):
            objs = list(safe_obtain(x) for x in proxy)
            return ptype(objs)

        return proxy

    if not hasattr(conn, 'obtain'):
        try:
            setattr(conn, 'obtain', conn.root.msgpack_dumps)
            setattr(conn, 'is_msgpack_obtain', True)
        except:
            # Fallback, compat only
            setattr(conn, 'obtain', conn.root.json_dumps)
            setattr(conn, 'is_msgpack_obtain', False)

    data = conn.obtain(proxy, compressed=True)
    data = zlib.decompress(data)

    if conn.is_msgpack_obtain:
        data = msgpack.loads(data)
    else:
        try:
            data = data.decode('utf-8')
        except:
            data = data.decode('latin1')

        data = json.loads(data) # should prevent any code execution

    return data

def obtain(proxy):
    return safe_obtain(proxy)

@contextmanager
def redirected_stdo(module, stdout=None, stderr=None):
    ns = module.client.conn.namespace
    if stdout is None:
        stdout = module.stdout
    if stderr is None:
        stderr = module.stdout

    try:
        ns['redirect_stdo'](
            restricted(
                stdout, ['softspace', 'write', 'flush']),
            restricted(
                stderr, ['softspace', 'write', 'flush']))

        module.client.conn.register_remote_cleanup(ns['reset_stdo'])

        yield

    finally:
        ns['reset_stdo']()
        module.client.conn.unregister_remote_cleanup(ns['reset_stdo'])

@contextmanager
def redirected_stdio(module, stdout=None, stderr=None):
    r"""
    Redirects the other party's ``stdin``, ``stdout`` and ``stderr`` to
    those of the local party, so remote IO will occur locally.

    Example usage::

        with redirected_stdio(conn):
            conn.modules.sys.stdout.write("hello\n")   # will be printed locally

    """

    ns = module.client.conn.namespace

    stdin = sys.stdin

    if stdout is None:
        stdout = module.stdout
    if stderr is None:
        stderr = module.stdout

    try:
        ns['redirect_stdio'](
            restricted(
                stdin, ['softspace', 'write', 'readline', 'encoding', 'close']),
            restricted(
                stdout, ['softspace', 'write', 'readline', 'encoding', 'close']),
            restricted(
                stderr, ['softspace', 'write', 'readline', 'encoding', 'close']))

        module.client.conn.register_remote_cleanup(ns['reset_stdio'])

        yield

    finally:
        ns['reset_stdio']()
        module.client.conn.unregister_remote_cleanup(ns['reset_stdio'])
