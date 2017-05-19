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
from .PupyPackagesDependencies import packages_dependencies, LOAD_PACKAGE, LOAD_DLL, EXEC, ALL_OS, WINDOWS, LINUX, ANDROID
from .PupyJob import PupyJob
from zipfile import ZipFile
import zlib
import marshal
import imp
import platform

ROOT=os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
LIBS_AUTHORIZED_PATHS = [x for x in sys.path if x != ''] + [os.path.join(ROOT,'packages')] + ['packages/']
logging.debug("LIBS_AUTHORIZED_PATHS=%s"%repr(LIBS_AUTHORIZED_PATHS))

class BinaryObjectError(ValueError):
    pass

def safe_file_exists(f):
    """ some file systems like vmhgfs are case insensitive and os.isdir() return True for "lAzAgNE", so we need this check for modules like LaZagne.py and lazagne gets well imported """
    return os.path.basename(f) in os.listdir(os.path.dirname(f))

class PupyClient(object):
    def __init__(self, desc, pupsrv):
        self.desc=desc
        self.powershell={'x64': {'object': None, 'scripts_loaded': []}, 'x86': {'object': None, 'scripts_loaded': []}}
        #alias
        self.conn=self.desc["conn"]
        self.pupsrv=pupsrv
        self.load_pupyimporter()
        self.imported_dlls={}

        #to reuse impersonated handle in other modules
        self.impersonated_dupHandle=None

    def __str__(self):
        return "PupyClient(id=%s, user=%s, hostname=%s, platform=%s)"%(self.desc["id"], self.desc["user"], self.desc["hostname"], self.desc["platform"])

    def __del__(self):
        del self.desc
        # close the powershell interpreter
        for arch in ['x64', 'x86']:
            if self.powershell[arch]['object']:
                self.powershell[arch]['object'].stdin.write("exit\n")
        del self.powershell

    def get_conf(self):
        dic={}
        if "offline_script" in self.desc:
            dic["offline_script"]=self.desc["offline_script"]
        dic["launcher"]=self.desc["launcher"]
        dic["launcher_args"]=self.desc["launcher_args"]
        return dic

    def short_name(self):
        try:
            return self.desc["platform"][0:3].lower()+"_"+self.desc["hostname"]+"_"+self.desc["macaddr"].replace(':','')
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
            if self.desc['platform']==platform.system() and self.desc['proc_arch']==platform.architecture()[0] and self.desc['os_arch']==platform.machine():
                return True

        except Exception as e:
            logging.error(e)
        return False

    def get_packages_path(self):
        """ return the list of path to search packages for depending on client OS and architecture """
        path = [
            os.path.join('packages', self.platform),
            os.path.join('packages', self.platform, 'all'),
        ]

        if self.is_posix() and not self.platform == 'posix':
            path.append(
                os.path.join('packages', 'posix', 'all')
            )

        if self.arch:
            path = path + [
                os.path.join(p, self.arch) for p in path
            ]

        path.append(os.path.join('packages', 'all'))

        path = path + [
            os.path.join(ROOT, p) for p in path
        ]

        return set(path)

    def load_pupyimporter(self):
        """ load pupyimporter in case it is not """
        if "pupyimporter" not in self.conn.modules.sys.modules:
            pupyimporter_code=""
            with open(os.path.join(ROOT, "packages","all","pupyimporter.py"),'rb') as f:
                pupyimporter_code=f.read()
            self.conn.execute(textwrap.dedent(
            """
            import imp
            import sys
            def pupyimporter_preimporter(code):
                mod = imp.new_module("pupyimporter")
                mod.__name__="pupyimporter"
                mod.__file__="<memimport>\\\\pupyimporter"
                mod.__package__="pupyimporter"
                sys.modules["pupyimporter"]=mod
                exec code+"\\n" in mod.__dict__
                mod.install()
                """))
            self.conn.namespace["pupyimporter_preimporter"](pupyimporter_code)

        pupyimporter = self.conn.modules.pupyimporter

        try:
            self.conn._conn.root.register_cleanup(pupyimporter.unregister_package_request_hook)
            pupyimporter.register_package_request_hook(self.remote_load_package)
        except:
            pass

        try:
            self.conn._conn.root.register_cleanup(pupyimporter.unregister_package_error_hook)
            pupyimporter.register_package_error_hook(self.remote_print_error)
        except:
            pass

    def load_dll(self, path):
        """
            load some dll from memory like sqlite3.dll needed for some .pyd to work
            Don't load pywintypes27.dll and pythoncom27.dll with this. Use load_package("pythoncom") instead
        """
        name = os.path.basename(path)
        if name in self.imported_dlls:
            return False

        buf = b""

        if not os.path.exists(path):
            path = None
            for packages_path in self.get_packages_path():
                packages_path = os.path.join(packages_path, name)
                if os.path.exists(packages_path):
                    with open(packages_path, 'rb') as f:
                        buf = f.read()
                        break

        if not buf and self.arch:
            arch_bundle = os.path.join(
                ROOT, 'payload_templates', self.platform+'-'+self.arch+'.zip'
            )

            if os.path.exists(arch_bundle):
                with ZipFile(arch_bundle, 'r') as bundle:
                    for info in bundle.infolist():
                        if info.filename.endswith('/'+name) or info.filename == name:
                            buf = bundle.read(info.filename)
                            break

        if not buf:
            raise ImportError("load_dll: couldn't find {}".format(name))

        if not self.conn.modules.pupy.load_dll(name, buf):
            raise ImportError("load_dll: couldn't load {}".format(name))

        self.imported_dlls[name]=True
        return True

    def load_package(self, module_name, force=False, new_deps=[]):
        if module_name in packages_dependencies:
            for t,o,v in packages_dependencies[module_name]:
                if o==ALL_OS or (o==ANDROID and self.is_android()) or (o==WINDOWS and self.is_windows()) or (o==LINUX and self.is_linux()):
                    if t==LOAD_PACKAGE:
                        if (self._load_package(v, force)):
                            new_deps.append(v)

                    elif t==LOAD_DLL:
                        self.load_dll(v)
                    elif t==EXEC:
                        self.conn.execute(v)
                    else:
                        raise PupyModuleError("Unknown package loading method %s"%t)

        if self._load_package(module_name, force):
            new_deps.append(module_name)
            return True

        return False

    def unload_package(self, module_name):
        if not module_name.endswith(('.so', '.dll')):
            self.conn.modules.pupyimporter.invalidate_module(module_name)

    def remote_load_package(self, module_name):
        logging.debug("remote module_name asked for : %s"%module_name)
        dic=self._load_package(module_name, force=False, remote=True)
        if not dic:
            logging.debug("no package %s found for remote client"%module_name)
        return dic

    def remote_print_error(self, msg):
        self.pupsrv.handler.display_warning(msg)

    def _get_module_dic(self, search_path, start_path, pure_python_only=False, remote=False, check_server_arch=False):
        modules_dic = {}
        found_files = set()
        module_path = os.path.join(search_path, start_path)

        if remote:
            if ".." in module_path or not module_path.startswith(tuple(LIBS_AUTHORIZED_PATHS)):
                logging.warning("Attempt to retrieve lib from unsafe path: %s"%module_path)
                return {}

        # loading a real package with multiple files
        if os.path.isdir(module_path) and safe_file_exists(module_path):
            for root, dirs, files in os.walk(module_path, followlinks=True):
                for f in files:
                    if root.endswith(('tests', 'test', 'SelfTest', 'examples')) or f.startswith('.#'):
                        continue

                    if check_server_arch:
                        # allow uploading compiled python extension from sys.path only if client arch match server arch
                        if f.endswith((".pyd",".dll")) and not (self.is_windows() and self.match_server_arch()):
                            raise BinaryObjectError('Path contains unsafe binary objects: {}'.format(f))
                        elif f.endswith(".so") and not (self.is_linux() and self.match_server_arch()):
                            raise BinaryObjectError('Path contains unsafe binary objects: {}'.format(f))

                    if pure_python_only and f.endswith((".so",".pyd",".dll")):
                        # avoid loosing shells when looking for packages in
                        # sys.path and unfortunatelly pushing a .so ELF on a
                        # remote windows
                        raise BinaryObjectError('Path contains binary objects: {}'.format(f))

                    if not f.endswith(('.so', '.pyd', '.dll', '.pyo', '.pyc', '.py')):
                        continue

                    module_code = b''
                    with open(os.path.join(root, f), 'rb') as fd:
                        module_code = fd.read()

                    modprefix = root[len(search_path.rstrip(os.sep))+1:]
                    modpath = os.path.join(modprefix,f).replace("\\","/")

                    base, ext = modpath.rsplit('.', 1)

                    # Garbage removing
                    if ext == 'py' and ( base+'.pyc' in modules_dic or base+'.pyo' in modules_dic ):
                        continue

                    elif ext == 'pyc':
                        if base+'.py' in modules_dic:
                            del modules_dic[base+'.py']

                        if base+'.pyo' in modules_dic:
                            continue
                    elif ext == 'pyo':
                        if base+'.py' in modules_dic:
                            del modules_dic[base+'.py']

                        if base+'.pyc' in modules_dic:
                            del modules_dic[base+'.pyc']

                    # Special case with pyd loaders
                    elif ext == 'pyd':
                        if base+'.py' in modules_dic:
                            del modules_dic[base+'.py']

                        if base+'.pyc' in modules_dic:
                            del modules_dic[base+'.pyc']

                        if base+'.pyo' in modules_dic:
                            del modules_dic[base+'.pyo']
                    if ext == "py":
                        module_code = '\0'*8 + marshal.dumps(
                            compile(module_code, modpath, 'exec')
                        )
                        modpath = base+'.pyc'
                    modules_dic[modpath] = module_code

                package_found=True
        else: # loading a simple file
            extlist=[ '.pyo', '.pyc', '.py'  ]
            if not pure_python_only:
                #quick and dirty ;) => pythoncom27.dll, pywintypes27.dll
                extlist+=[ '.so', '.pyd', '27.dll' ]

            for ext in extlist:
                filepath = os.path.join(module_path+ext)
                if os.path.isfile(filepath) and safe_file_exists(filepath):
                    if check_server_arch:
                        # allow uploading compiled python extension from sys.path only if client arch match server arch
                        if filepath.endswith((".pyd",".dll")) and not (self.is_windows() and self.match_server_arch()):
                            continue
                        elif filepath.endswith(".so") and not (self.is_linux() and self.match_server_arch()):
                            continue
                    module_code = ''
                    with open(filepath,'rb') as f:
                        module_code=f.read()

                    cur = ''
                    for rep in start_path.split('/')[:-1]:
                        if not cur+rep+'/__init__.py' in modules_dic:
                            modules_dic[rep+'/__init__.py']=''
                        cur+=rep+'/'

                    if ext == '.py':
                        module_code = '\0'*8 + marshal.dumps(
                            compile(module_code, start_path+ext, 'exec')
                        )
                        ext = '.pyc'

                    modules_dic[start_path+ext] = module_code

                    package_found=True
                    break

        return modules_dic

    def _load_package(self, module_name, force=False, remote=False):
        """
            load a python module into memory depending on what OS the client is.
            This function can load all types of modules in memory for windows both x86 and amd64 including .pyd C extensions
            For other platforms : loading .so in memory is not supported yet.
        """
        # start path should only use "/" as separator

        update = False
        pupyimporter = self.conn.modules.pupyimporter
        initial_module_name = module_name

        if not remote and not module_name.endswith(('.dll', '.so')):
            if pupyimporter.has_module(module_name):
                if not force:
                    return False
                else:
                    update = True
                    pupyimporter.invalidate_module(module_name)

        start_path=module_name.replace(".", "/")
        package_found=False
        package_path=None
        for search_path in self.get_packages_path():
            try:
                modules_dic=self._get_module_dic(search_path, start_path, remote=remote)
                if modules_dic:
                    package_path=search_path
                    break
            except Exception as e:
                if remote:
                    return False
                else:
                    raise PupyModuleError(
                        "Error while loading package {}: {}".format(
                            module_name, traceback.format_exc()))

        if not modules_dic and self.arch:
            arch_bundle = os.path.join(
                ROOT, 'payload_templates', self.platform+'-'+self.arch+'.zip'
            )

            if os.path.exists(arch_bundle):
                modules_dic = {}

                with ZipFile(arch_bundle, 'r') as bundle:

                    # ../libs - for windows bundles, to use simple zip command
                    # site-packages/win32 - for pywin32
                    possible_prefixes = (
                        '',
                        'site-packages/win32/lib',
                        'site-packages/win32',
                        'site-packages/pywin32_system32',
                        'site-packages',
                        'lib-dynload'
                    )

                    endings = (
                        '/', '.pyo', '.pyc', '.py', '.pyd', '.so', '.dll'
                    )

                    # Horrible pywin32..
                    if module_name in ( 'pythoncom', 'pythoncomloader', 'pywintypes' ):
                        endings = tuple([ '27.dll' ])

                    start_paths = tuple([
                        ('/'.join([x, start_path])).strip('/')+y \
                            for x in possible_prefixes \
                            for y in endings
                    ])

                    for info in bundle.infolist():
                        if info.filename.startswith(start_paths):
                            module_name = info.filename
                            for prefix in possible_prefixes:
                                if module_name.startswith(prefix+'/'):
                                    module_name = module_name[len(prefix)+1:]
                                    break

                            try:
                                base, ext = module_name.rsplit('.', 1)
                            except:
                                continue

                            # Garbage removing
                            if ext == 'py' and ( base+'.pyc' in modules_dic or base+'.pyo' in modules_dic ):
                                continue

                            elif ext == 'pyc':
                                if base+'.py' in modules_dic:
                                    del modules_dic[base+'.py']

                                if base+'.pyo' in modules_dic:
                                    continue
                            elif ext == 'pyo':
                                if base+'.py' in modules_dic:
                                    del modules_dic[base+'.py']

                                if base+'.pyc' in modules_dic:
                                    del modules_dic[base+'.pyc']

                            # Special case with pyd loaders
                            elif ext == 'pyd':
                                if base+'.py' in modules_dic:
                                    del modules_dic[base+'.py']

                                if base+'.pyc' in modules_dic:
                                    del modules_dic[base+'.pyc']

                                if base+'.pyo' in modules_dic:
                                    del modules_dic[base+'.pyo']

                            modules_dic[module_name] = bundle.read(info.filename)

        # in last resort, attempt to load the package from the server's sys.path if it exists
        if not modules_dic:
            for search_path in sys.path:
                try:
                    modules_dic = self._get_module_dic(
                        search_path, start_path, pure_python_only=False, remote=remote, check_server_arch=True
                    )

                    if modules_dic:
                        logging.info("package %s not found in packages/, but found in local sys.path, attempting to push it remotely..." % initial_module_name)
                        package_path=search_path
                        break

                except BinaryObjectError as e:
                    logging.warning(e)

                except Exception as e:
                    if remote:
                        return False
                    else:
                        raise PupyModuleError(
                            "Error while loading package from sys.path {}: {}".format(
                                initial_module_name, traceback.format_exc()))
        if not modules_dic:
            if remote:
                return False
            else:
                raise PupyModuleError("Couldn't find package: {}".format(module_name))

        # we have to pickle the dic for two reasons : because the remote side is
        # not aut0horized to iterate/access to the dictionary declared on this
        # side and because it is more efficient
        pupyimporter.pupy_add_package(
            zlib.compress(cPickle.dumps(modules_dic), 9),
            compressed=True,
            # Use None to prevent import-then-clean-then-search behavior
            name=(None if remote else initial_module_name)
        )

        logging.debug("package %s loaded on %s from path=%s"%(initial_module_name, self.short_name(), package_path))

        return True

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
