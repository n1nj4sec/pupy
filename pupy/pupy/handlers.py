# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
__all__ = ('set_sighandlers',)

import os
import signal

import pupy


logger = pupy.get_logger('signals')


def _defered_close_exit(connection):
    logger.warning('Defered close+exit')

    logger.info('Terminating client')

    pupy.client.terminate()

    logger.info('Closing connection')
    if pupy.connection:
        pupy.connection.close()

    logger.info('Done')


def _handle_sigchld(*args, **kwargs):
    os.waitpid(-1, os.WNOHANG)


def _handle_sighup(*args):
    logger.debug('SIGHUP')


def _handle_sigterm(*args):
    logger.warning('SIGTERM')

    if pupy.manager:
        try:
            pupy.manager.event(pupy.Manager.TERMINATE)
        except Exception as e:
            logger.exception(e)

    try:
        # Should be the custom event, as generated on client
        pupy.broadcast_event(0x10000000 | 0xFFFF)
        logger.info('Event broadcasted')
    except Exception as e:
        logger.exception(e)

    if pupy.connection:
        pupy.connection.defer(
            logger.exception,
            _defered_close_exit,
            pupy.connection
        )
    else:
        _defered_close_exit(None)

    logger.warning('SIGTERM HANDLED')


def set_sighandlers():
    if hasattr(signal, 'SIGHUP'):
        try:
            signal.signal(signal.SIGHUP, _handle_sighup)
        except Exception as e:
            logger.exception(e)

    if hasattr(signal, 'SIGTERM'):
        try:
            signal.signal(signal.SIGTERM, _handle_sigterm)
        except Exception as e:
            logger.exception(e)

    if pupy.is_supported(pupy.set_exit_session_callback):
        try:
            pupy.set_exit_session_callback(_handle_sigterm)
        except Exception as e:
            logger.exception(e)
