# ===================================================================
#
# Copyright (c) 2014, Legrandin <helderijs@gmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
# ===================================================================

import abc
from Crypto.Util.py3compat import byte_string

#
# List of file suffixes for Python extensions
#

import imp
extension_suffixes = []
for ext, mod, typ in imp.get_suffixes():
    if typ == imp.C_EXTENSION:
        extension_suffixes.append(ext)

_buffer_type = (bytearray, memoryview)

class _VoidPointer(object):
    @abc.abstractmethod
    def get(self):
        """Return the memory location we point to"""
        return

    @abc.abstractmethod
    def address_of(self):
        """Return a raw pointer to this pointer"""
        return


import ctypes
from ctypes import (CDLL, c_void_p, byref, c_ubyte)
from ctypes.util import find_library
from ctypes import Array as _Array

from ctypes import create_string_buffer
from ctypes import c_size_t

assert(create_string_buffer)
assert(c_size_t)

null_pointer = None

def load_lib(name, cdecl):
    import platform
    bits, linkage = platform.architecture()
    if "." not in name and not linkage.startswith("Win"):
        full_name = find_library(name)
        if full_name is None:
            raise OSError("Cannot load library '%s'" % name)
        name = full_name
    return CDLL(name)

def get_c_string(c_string):
    return c_string.value

def get_raw_buffer(buf):
    return buf.raw

# ---- Get raw pointer ---

_PyBUF_SIMPLE = 0
_PyObject_GetBuffer = ctypes.pythonapi.PyObject_GetBuffer
_py_object = ctypes.py_object
_c_ssize_t = ctypes.c_ssize_t
_c_ssize_p = ctypes.POINTER(_c_ssize_t)

# See Include/object.h for CPython
# and https://github.com/pallets/click/blob/master/click/_winconsole.py
class _Py_buffer(ctypes.Structure):
    _fields_ = [
        ('buf',         c_void_p),
        ('obj',         ctypes.py_object),
        ('len',         _c_ssize_t),
        ('itemsize',    _c_ssize_t),
        ('readonly',    ctypes.c_int),
        ('ndim',        ctypes.c_int),
        ('format',      ctypes.c_char_p),
        ('shape',       _c_ssize_p),
        ('strides',     _c_ssize_p),
        ('suboffsets',  _c_ssize_p),
        ('internal',    c_void_p),
        ('smalltable', _c_ssize_t * 2)
    ]

def c_uint8_ptr(data):
    if byte_string(data) or isinstance(data, _Array):
        return data
    elif isinstance(data, _buffer_type):
        obj = _py_object(data)
        buf = _Py_buffer()
        _PyObject_GetBuffer(obj, byref(buf), _PyBUF_SIMPLE)
        buffer_type = c_ubyte * buf.len
        return buffer_type.from_address(buf.buf)
    else:
        raise TypeError("Object type %s cannot be passed to C code" % type(data))

# ---

class VoidPointer_ctypes(_VoidPointer):
    """Model a newly allocated pointer to void"""

    def __init__(self):
        self._p = c_void_p()

    def get(self):
        return self._p

    def address_of(self):
        return byref(self._p)

def VoidPointer():
    return VoidPointer_ctypes()

backend = "ctypes"
del ctypes

class SmartPointer(object):
    """Class to hold a non-managed piece of memory"""

    def __init__(self, raw_pointer, destructor):
        self._raw_pointer = raw_pointer
        self._destructor = destructor

    def get(self):
        return self._raw_pointer

    def release(self):
        rp, self._raw_pointer = self._raw_pointer, None
        return rp

    def __del__(self):
        try:
            if self._raw_pointer is not None:
                self._destructor(self._raw_pointer)
                self._raw_pointer = None
        except AttributeError:
            pass


def is_buffer(x):
    """Return True if object x supports the buffer interface"""
    return isinstance(x, (bytes, bytearray, memoryview))

def is_writeable_buffer(x):
    return (isinstance(x, bytearray) or
            (isinstance(x, memoryview) and not x.readonly))

def load_pycryptodome_raw_lib(name, cdecl):
    """Load a shared library and return a handle to it.

    @name,  the name of the library expressed as a PyCryptodome module,
            for instance Crypto.Cipher._raw_cbc.

    @cdecl, the C function declarations.
    """

    attempts = []
    basename = '/'.join(name.split('.'))
    for ext in extension_suffixes:
        try:
            filename = basename + ext
            return CDLL(filename)
        except OSError, exp:
            attempts.append("Trying '%s': %s" % (filename, str(exp)))

    raise OSError("Cannot load native module '%s': %s (%s)" % (name, ", ".join(attempts), exp))

def expect_byte_string(data):
    raise NotImplementedError("To be removed")
