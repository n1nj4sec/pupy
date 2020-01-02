# -*- encoding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
__all__ = (
    'memfd_create', 'memfd_is_supported'
)

try:
    from _pupy import (
        memfd_create, memfd_is_supported
    )

except ImportError:
    import os
    import sys
    import ctypes
    import platform

    import pupy

    SELF = ctypes.CDLL(None)
    syscall = SELF.syscall


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
