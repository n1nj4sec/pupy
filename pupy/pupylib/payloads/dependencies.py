#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import cPickle
import zlib
from zipfile import ZipFile

from elftools.elf.elffile import ELFFile
from io import BytesIO

from pupylib.PupyCompile import pupycompile
from pupylib import ROOT, getLogger

class BinaryObjectError(ValueError):
    pass

class UnsafePathError(ValueError):
    pass

class NotFoundError(NameError):
    pass

class IgnoreFileException(Exception):
    pass

logger = getLogger('deps')

LIBS_AUTHORIZED_PATHS = [
    x for x in sys.path if x != ''
] + [
    os.path.join(ROOT, 'packages'),
    'packages'
]

PATCHES_PATHS = [
    os.path.abspath(os.path.join(os.getcwdu(), 'packages', 'patches')),
    os.path.abspath(os.path.join(ROOT, 'packages', 'patches')),
    os.path.abspath(os.path.join(ROOT, 'library_patches'))
]

# ../libs - for windows bundles, to use simple zip command
# site-packages/win32 - for pywin32
COMMON_SEARCH_PREFIXES = (
    '',
    'site-packages/win32/lib',
    'site-packages/win32',
    'site-packages/pywin32_system32',
    'site-packages',
    'lib-dynload'
)

COMMON_MODULE_ENDINGS = (
    '/', '.py', '.pyo', '.pyc', '.pyd', '.so', '.dll'
)

# dependencies to load for each modules
WELL_KNOWN_DEPS = {
    'pupwinutils.memexec': {
        'all': [
            'pupymemexec'
        ],
    },
    'pupyutils.basic_cmds': {
        'windows': ['junctions', 'ntfs_streams', '_scandir'],
        'linux': ['xattr', '_scandir'],
        'all': [
            'pupyutils', 'scandir', 'zipfile',
            'tarfile', 'scandir', 'fsutils'
        ],
    },
    'dbus': {
        'linux': [
            '_dbus_bindings', 'pyexpat'
        ]
    },
    'sqlite3': {
        'all': ['_sqlite3'],
        'windows': ['sqlite3.dll'],
    },
    'xml': {
        'all': ['xml.etree']
    },
    'secretstorage': {
        'linux': ['dbus']
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
    'OpenSSL': {
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

logger.debug("LIBS_AUTHORIZED_PATHS=%s"%repr(LIBS_AUTHORIZED_PATHS))

def remove_dt_needed(data, libname):
    ef = ELFFile(data)
    dyn = ef.get_section_by_name('.dynamic')

    ent_size = dyn.header.sh_entsize
    sect_size = dyn.header.sh_size
    sect_offt = dyn.header.sh_offset

    tag_idx = None

    for idx in xrange(sect_size/ent_size):
        tag = dyn.get_tag(idx)
        if tag['d_tag'] == 'DT_NEEDED':
            if tag.needed == libname:
                tag_idx = idx
                break

    if tag_idx is None:
        return False

    null_tag = '\x00' * ent_size
    dynamic_tail = None

    if idx == 0:
        dynamic_tail = dyn.data()[ent_size:] + null_tag
    else:
        dyndata = dyn.data()
        dynamic_tail = dyndata[:ent_size*(idx)] + \
          dyndata[ent_size*(idx+1):] + null_tag

    data.seek(sect_offt)
    data.write(dynamic_tail)
    return True


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

def importer(dependencies, os='all', arch=None, path=None, posix=None, native=False):
    if path:
        modules = {}
        if not type(dependencies) in (list, tuple, set, frozenset):
            dependencies = [dependencies]

        for dependency in dependencies:
            modules.update(from_path(os, arch, path, dependency))

        blob = cPickle.dumps(modules)
        blob = zlib.compress(blob, 9)
    else:
        blob, modules, _ = package(dependencies, os, arch, posix=posix, native=native)

    return 'pupyimporter.pupy_add_package({}, compressed=True)'.format(repr(blob))

def modify_native_content(filename, content):
    if content.startswith('\x7fELF'):
        logger.info('ELF file - %s, check for libpython DT_NEED record', filename)
        image = BytesIO(content)
        if remove_dt_needed(image, 'libpython2.7.so.1.0'):
            logger.info('Modified: DT_NEEDED libpython2.7.so.1.0 removed')

        content = image.getvalue()

    return content

def get_content(platform, arch, prefix, filepath, archive=None, honor_ignore=True, native=False):
    if filepath.startswith(prefix) and honor_ignore:
        basepath = filepath[len(prefix)+1:]
        basepath, ext = os.path.splitext(basepath)
        if ext in ('.pyo', 'py', '.pyc'):
            ext = '.py'
        basepath = basepath+ext

        arch_prefixes = ['all']
        if platform:
            arch_prefixes.append(platform)
            arch_prefixes.append(os.path.join(platform, 'all'))

            if arch:
                arch_prefixes.append(os.path.join(platform, arch))

        for patch_prefix in PATCHES_PATHS:
            if not os.path.isdir(patch_prefix):
                continue

            for arch_prefix in arch_prefixes:
                patch_dir = os.path.join(patch_prefix, arch_prefix)

                if not os.path.isdir(patch_dir):
                    continue

                maybe_patch = os.path.join(patch_dir, basepath)
                if os.path.exists(maybe_patch):
                    logger.info('Patch: %s -> %s', filepath, maybe_patch)
                    with open(maybe_patch, 'rb') as filedata:
                        return filedata.read()
                elif os.path.exists(maybe_patch+'.ignore'):
                    logger.info('Patch: Ignore %s', filepath)
                    raise IgnoreFileException()
                elif os.path.exists(maybe_patch+'.include'):
                    break
                else:
                    subpaths = basepath.split(os.path.sep)
                    for i in xrange(len(subpaths)):
                        ignore = [patch_dir] + subpaths[:i]
                        ignore.append('.ignore')
                        ignore = os.path.sep.join(ignore)
                        if os.path.exists(ignore):
                            logger.info('Patch: Ignore %s (%s)', filepath, ignore)
                            raise IgnoreFileException()

    content = None

    if archive:
        content = archive.read(filepath)
    else:
        with open(filepath, 'rb') as filedata:
            content = filedata.read()

    if not native:
        logger.debug('Modify natve content for %s (native=%s)', filepath, bool(native))
        content = modify_native_content(filepath, content)

    return content

def from_path(platform, arch, search_path, start_path, pure_python_only=False,
              remote=False, honor_ignore=True, native=False):

    query = start_path

    modules_dic = {}

    if os.path.sep not in start_path:
        start_path = start_path.replace('.', os.path.sep)

    module_path = os.path.join(search_path, start_path)

    if remote:
        if '..' in module_path or not module_path.startswith(tuple(LIBS_AUTHORIZED_PATHS)):
            raise UnsafePathError('Attempt to retrieve lib from unsafe path: {} (query={})'.format(
                module_path, query))

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
                    raise BinaryObjectError('Path contains binary objects: {} (query={})'.format(
                        f, query))

                if not f.endswith(('.so', '.pyd', '.dll', '.pyo', '.pyc', '.py')):
                    continue

                try:
                    module_code = get_content(
                        platform,
                        arch,
                        search_path,
                        os.path.join(root, f),
                        honor_ignore=honor_ignore,
                        native=native)
                except IgnoreFileException:
                    continue

                modprefix = root[len(search_path.rstrip(os.sep))+1:]
                modpath = os.path.join(modprefix,f).replace("\\","/")

                base, ext = modpath.rsplit('.', 1)

                # Garbage removing
                if ext == 'py' and base+'.pyo' not in modules_dic:
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

    else: # loading a simple file
        extlist = ['.py', '.pyo', '.pyc']
        if not pure_python_only:
            #quick and dirty ;) => pythoncom27.dll, pywintypes27.dll
            extlist += ['.so', '.pyd', '27.dll']

        for ext in extlist:
            filepath = os.path.join(module_path+ext)
            if os.path.isfile(filepath) and safe_file_exists(filepath):
                try:
                    module_code = get_content(
                        platform,
                        arch,
                        search_path,
                        filepath,
                        honor_ignore=honor_ignore,
                        native=native)
                except IgnoreFileException:
                    break

                cur = ''
                for rep in start_path.split('/')[:-1]:
                    if cur+rep+'/__init__.py' not in modules_dic:
                        modules_dic[rep+'/__init__.py']=''
                    cur+=rep+'/'

                if ext == '.py':
                    module_code = pupycompile(module_code, start_path+ext)
                    ext = '.pyo'

                modules_dic[start_path+ext] = module_code

                break

    return modules_dic

def paths(platform='all', arch=None, posix=None):
    """ return the list of path to search packages for depending on client OS and architecture """

    if posix is None:
        posix = platform.lower() != 'windows'

    path = [
        os.path.join('packages', platform),
        os.path.abspath(os.path.join(ROOT, 'library_patches'))
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

def _package(modules, module_name, platform, arch, remote=False, posix=None, honor_ignore=True, native=False):

    initial_module_name = module_name

    start_path = module_name.replace('.', os.path.sep)

    for search_path in paths(platform, arch, posix):
        modules_dic = from_path(
            platform, arch, search_path, start_path,
            remote=remote, honor_ignore=honor_ignore,
            native=native)
        if modules_dic:
            break

    if not modules_dic and arch:
        archive = bundle(platform, arch)
        if archive:
            modules_dic = {}

            endings = COMMON_MODULE_ENDINGS

            # Horrible pywin32..
            if module_name in ('pythoncom', 'pythoncomloader', 'pywintypes'):
                endings = tuple(['27.dll'])

            start_paths = tuple([
                ('/'.join([x, start_path])).strip('/')+y \
                    for x in COMMON_SEARCH_PREFIXES \
                    for y in endings
            ])

            for info in archive.infolist():
                content = None
                if info.filename.startswith(start_paths):
                    module_name = info.filename

                    for prefix in COMMON_SEARCH_PREFIXES:
                        if module_name.startswith(prefix+'/'):
                            module_name = module_name[len(prefix)+1:]
                            break

                    try:
                        base, ext = module_name.rsplit('.', 1)
                    except:
                        continue

                    # Garbage removing
                    if ext == 'py' and base+'.pyo' not in modules_dic:
                        try:
                            content = pupycompile(
                                get_content(
                                    platform, arch, prefix,
                                    info.filename, archive,
                                    honor_ignore=honor_ignore,
                                    native=native),
                                info.filename)
                        except IgnoreFileException:
                            continue

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
                        try:
                            content = get_content(
                                platform, arch, prefix,
                                info.filename, archive,
                                honor_ignore=honor_ignore,
                                native=native)
                        except IgnoreFileException:
                            continue

                    if content:
                        modules_dic[base+'.'+ext] = content

            archive.close()

    # in last resort, attempt to load the package from the server's sys.path if it exists
    if not modules_dic:
        for search_path in sys.path:
            try:
                modules_dic = from_path(
                    platform, arch,
                    search_path, start_path, pure_python_only=True, remote=remote
                )

                if modules_dic:
                    logger.info('package %s not found in packages/, but found in local sys.path'
                                     ', attempting to push it remotely...' % initial_module_name)
                    break

            except BinaryObjectError as e:
                logger.warning(e)

            except UnsafePathError as e:
                logger.error(e)

    if not modules_dic:
        raise NotFoundError(module_name)

    modules.update(modules_dic)

def package(requirements, platform, arch, remote=False, posix=False,
            filter_needed_cb=None, honor_ignore=True, native=False):
    dependencies = set()

    if not type(requirements) in (list, tuple, set, frozenset):
        requirements = [requirements]

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
                remote=remote, posix=posix,
                honor_ignore=honor_ignore,
                native=native
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

def dll(name, platform, arch, honor_ignore=True, native=False):
    buf = b''

    for packages_path in paths(platform, arch):
        dll_path = os.path.join(packages_path, name)
        if os.path.exists(dll_path):
            try:
                buf = get_content(
                    platform, arch, name, packages_path, dll_path,
                    honor_ignore=honor_ignore, native=native)
            except IgnoreFileException:
                pass

            break

    if not buf and arch:
        archive = bundle(platform, arch)
        if archive:
            for info in archive.infolist():
                if info.filename.endswith('/'+name) or info.filename == name:
                    try:
                        buf = get_content(
                            platform, arch, os.path.dirname(info.filename),
                            info.filename,
                            archive,
                            honor_ignore=honor_ignore,
                            native=native
                        )
                    except IgnoreFileException:
                        pass

                    break

            archive.close()

    if not buf:
        raise NotFoundError(name)

    return buf
