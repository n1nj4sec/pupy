#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os, sys, os.path, logging
import cPickle
import marshal
import zlib
from zipfile import ZipFile
from ..PupyCompile import pupycompile

import traceback

class BinaryObjectError(ValueError):
    pass

class NotFoundError(NameError):
    pass

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))

LIBS_AUTHORIZED_PATHS = [
    x for x in sys.path if x != ''
] + [
    os.path.join(ROOT, 'packages'),
    'packages'
]

# dependencies to load for each modules
WELL_KNOWN_DEPS = {
    'pupwinutils.memexec': {
        'all': [
            'pupymemexec'
        ],
    },
    'pupyutils.basic_cmds': {
        'windows': [ 'junctions' ]
    },
    'dbus': {
        'linux': [
            '_dbus_bindings', 'pyexpat'
        ]
    },
    'sqlite3': {
        'all': [ '_sqlite3' ],
        'windows': [ 'sqlite3.dll' ],
    },
    'xml': {
        'all': [ '_elementtree', 'xml.etree' ]
    },
    'secretstorage': {
        'linux': [ 'dbus' ]
    },
    'memorpy': {
        'windows': [
            'win32api',
            'win32security'
        ]
    },
    'scapy': {
        'windows': [
            'pythoncom',
            'cryptography'
        ]
    },
    'win32com': {
        'windows': [
            'pythoncom',
        ]
    },
    'pyaudio': {
        'all': [
            '_portaudio'
        ]
    },
    'OpenSSL' : {
        'all': [
            'six',
            'enum',
            'cryptography',
            '_cffi_backend',
            'plistlib',
            'uu',
            'quopri',
            'pyparsing',
            'pkg_resources',
            'pprint',
            'ipaddress',
            'idna',
            'unicodedata',
        ]
    }
}

logging.debug("LIBS_AUTHORIZED_PATHS=%s"%repr(LIBS_AUTHORIZED_PATHS))

def safe_file_exists(f):
    """ some file systems like vmhgfs are case insensitive and os.isdir() return True for "lAzAgNE", so we need this check for modules like LaZagne.py and lazagne gets well imported """
    return os.path.basename(f) in os.listdir(os.path.dirname(f))

def loader(code, modulename):
    code = '''
import imp, sys, marshal
fullname = {}
mod = imp.new_module(fullname)
mod.__file__ = "<bootloader>/%s.pyo" % fullname
exec marshal.loads({}) in mod.__dict__
sys.modules[fullname]=mod
'''.format(
        repr(modulename),
        repr(pupycompile(code, modulename, raw=True)))

    return code

def importer(dependencies, os='all', arch=None, path=None, posix=None):
    if path:
        modules = {}
        if not type(dependencies) in (list, tuple, set, frozenset):
            dependencies = [ dependencies ]

        for dependency in dependencies:
            modules.update(from_path(path, dependency))

        blob = cPickle.dumps(modules)
        blob = zlib.compress(blob, 9)
    else:
        blob, modules, _ = package(dependencies, os, arch, posix=posix)

    return 'pupyimporter.pupy_add_package({}, compressed=True)'.format(repr(blob))

def from_path(search_path, start_path, pure_python_only=False, remote=False):
    modules_dic = {}
    found_files = set()

    if not os.path.sep in start_path:
        start_path = start_path.replace('.', os.path.sep)

    module_path = os.path.join(search_path, start_path)

    if remote:
        if '..' in module_path or not module_path.startswith(tuple(LIBS_AUTHORIZED_PATHS)):
            logging.warning("Attempt to retrieve lib from unsafe path: %s"%module_path)
            return {}

    # loading a real package with multiple files
    if os.path.isdir(module_path) and safe_file_exists(module_path):
        for root, dirs, files in os.walk(module_path, followlinks=True):
            for f in files:
                if root.endswith(('tests', 'test', 'SelfTest', 'examples')) or f.startswith('.#'):
                    continue

                if pure_python_only and f.endswith(('.so', '.pyd', '.dll')):
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
                if ext == 'py' and not base+'.pyo' in modules_dic:
                    module_code = pupycompile(module_code, modpath)
                    modpath = base+'.pyo'
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

                    if base+'.pyo' in modules_dic:
                        continue

                # Special case with pyd loaders
                elif ext == 'pyd':
                    if base+'.py' in modules_dic:
                        del modules_dic[base+'.py']

                    if base+'.pyc' in modules_dic:
                        del modules_dic[base+'.pyc']

                    if base+'.pyo' in modules_dic:
                        del modules_dic[base+'.pyo']

                modules_dic[modpath] = module_code

            package_found=True
    else: # loading a simple file
        extlist=[ '.py', '.pyo', '.pyc' ]
        if not pure_python_only:
            #quick and dirty ;) => pythoncom27.dll, pywintypes27.dll
            extlist+=[ '.so', '.pyd', '27.dll' ]

        for ext in extlist:
            filepath = os.path.join(module_path+ext)
            if os.path.isfile(filepath) and safe_file_exists(filepath):
                module_code = ''
                with open(filepath,'rb') as f:
                    module_code=f.read()

                cur = ''
                for rep in start_path.split('/')[:-1]:
                    if not cur+rep+'/__init__.py' in modules_dic:
                        modules_dic[rep+'/__init__.py']=''
                    cur+=rep+'/'

                if ext == '.py':
                    module_code = pupycompile(module_code, start_path+ext)
                    ext = '.pyo'

                modules_dic[start_path+ext] = module_code

                package_found=True
                break

    return modules_dic

def paths(platform='all', arch=None, posix=None):
    """ return the list of path to search packages for depending on client OS and architecture """

    if posix is None:
        posix = platform.lower() != 'windows'

    path = [
        os.path.join('packages', platform),
        os.path.abspath(os.path.join(ROOT, '..', 'client', 'library_patches'))
    ]

    if arch:
        path = path + [
            os.path.join(p, arch) for p in path
        ]

    if posix:
        path.append(
            os.path.join('packages', 'posix')
        )

    path = path + [
        os.path.join(p, 'all') for p in path
    ]

    path.append(os.path.join('packages', 'all'))

    path = path + [
        os.path.join(ROOT, p) for p in path
    ]

    return [
        x for x in path if os.path.isdir(x)
    ]


def _dependencies(module_name, os, dependencies):
    if module_name in dependencies:
        return

    dependencies.add(module_name)

    mod_deps = WELL_KNOWN_DEPS.get(module_name, {})
    for dependency in mod_deps.get('all', []) + mod_deps.get(os, []):
        _dependencies(dependency, os, dependencies)

def _package(modules, module_name, platform, arch, remote=False, posix=None):

    initial_module_name = module_name

    start_path = module_name.replace('.', os.path.sep)
    package_found = False

    for search_path in paths(platform, arch, posix):
        modules_dic = from_path(search_path, start_path, remote=remote)
        if modules_dic:
            break

    if not modules_dic and arch:
        archive = bundle(platform, arch)
        if archive:
            modules_dic = {}

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
                '/', '.py', '.pyo', '.pyc', '.pyd', '.so', '.dll'
            )

            # Horrible pywin32..
            if module_name in ( 'pythoncom', 'pythoncomloader', 'pywintypes' ):
                endings = tuple([ '27.dll' ])

            start_paths = tuple([
                ('/'.join([x, start_path])).strip('/')+y \
                    for x in possible_prefixes \
                    for y in endings
            ])

            for info in archive.infolist():
                content = None
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
                    if ext == 'py' and not base+'.pyo' in modules_dic:
                        content = pupycompile(
                            archive.read(info.filename), info.filename)
                        ext = 'pyo'

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

                        if base+'.pyo' in modules_dic:
                            continue
                    # Special case with pyd loaders
                    elif ext == 'pyd':
                        if base+'.py' in modules_dic:
                            del modules_dic[base+'.py']

                        if base+'.pyc' in modules_dic:
                            del modules_dic[base+'.pyc']

                        if base+'.pyo' in modules_dic:
                            del modules_dic[base+'.pyo']

                    if not content:
                        content = archive.read(info.filename)

                    modules_dic[base+'.'+ext] = content

            archive.close()

    # in last resort, attempt to load the package from the server's sys.path if it exists
    if not modules_dic:
        for search_path in sys.path:
            try:
                modules_dic = from_path(
                    search_path, start_path, pure_python_only=True, remote=remote
                )

                if modules_dic:
                    logging.info('package %s not found in packages/, but found in local sys.path'
                                     ', attempting to push it remotely...' % initial_module_name)
                    break

            except BinaryObjectError as e:
                logging.warning(e)

    if not modules_dic:
        raise NotFoundError(module_name)

    modules.update(modules_dic)

def package(requirements, platform, arch, remote=False, posix=False, filter_needed_cb=None):
    dependencies = set()

    if not type(requirements) in (list, tuple, set, frozenset):
        requirements = [ requirements ]

    for requirement in requirements:
        _dependencies(requirement, platform, dependencies)

    package_deps = set()
    dll_deps = set()

    for dependency in dependencies:
        if dependency.endswith(('.so', '.dll')):
            dll_deps.add(dependency)
        else:
            package_deps.add(dependency)

    if filter_needed_cb:
        if package_deps:
            package_deps = filter_needed_cb(package_deps, False)

        if dll_deps:
            dll_deps = filter_needed_cb(dll_deps, True)

    blob = b''
    contents = []
    dlls = []

    if package_deps:
        modules = {}

        for dependency in package_deps:
            _package(
                modules, dependency, platform, arch,
                remote=remote, posix=posix
            )

        blob = zlib.compress(cPickle.dumps(modules), 9)
        contents = list(dependencies)

    if dll_deps:
        for dependency in dll_deps:
            dlls.append((dependency, dll(dependency, platform, arch)))

    return blob, contents, dlls


def bundle(platform, arch):
    arch_bundle = os.path.join(
        'payload_templates', platform+'-'+arch+'.zip'
    )

    if not os.path.isfile(arch_bundle):
        arch_bundle = os.path.join(
            ROOT, 'payload_templates', platform+'-'+arch+'.zip'
        )

    if not os.path.exists(arch_bundle):
        return None

    return ZipFile(arch_bundle, 'r')

def dll(name, platform, arch):
    buf = b''

    path = None
    for packages_path in paths(platform, arch):
        packages_path = os.path.join(packages_path, name)
        if os.path.exists(packages_path):
            with open(packages_path, 'rb') as f:
                buf = f.read()
                break

    if not buf and arch:
        archive = bundle(platform, arch)
        if archive:
            for info in archive.infolist():
                if info.filename.endswith('/'+name) or info.filename == name:
                    buf = archive.read(info.filename)
                    break

            archive.close()

    if not buf:
        raise NotFoundError(name)

    return buf
