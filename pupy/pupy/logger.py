# -*- coding: utf-8 -*-

__all__ = ('create_root_logger', 'enable_debug_logger')

from os import path, getpid
from time import time

import logging
import tempfile


def create_root_logger(loglevel=logging.WARNING):
    logging.basicConfig()
    root_logger = logging.getLogger()
    root_logger.setLevel(loglevel)

    return root_logger.getChild('pupy')


def enable_debug_logger(root_logger):
    root_logger.handlers = []

    log_file_path = path.join(
        tempfile.mkdtemp(prefix='pupy-'),
        'pupy-client-{}-{}-debug.log'.format(
            int(time()), getpid()))

    log_to_file = logging.FileHandler(log_file_path)
    log_to_file.setLevel(logging.DEBUG)
    log_to_file.setFormatter(
        logging.Formatter(
            '%(asctime)-15s|%(levelname)-5s|%(relativeCreated)6d|%(threadName)s|%(name)s| %(message)s'))

    log_to_con = logging.StreamHandler()
    log_to_con.setLevel(logging.DEBUG)
    log_to_con.setFormatter(logging.Formatter('%(asctime)-15s| %(message)s'))

    root_logger.addHandler(log_to_file)
    # root_logger.addHandler(log_to_con)
    root_logger.setLevel(logging.DEBUG)

    root_logger.info('LogFile: %s', log_file_path)

    return log_file_path
