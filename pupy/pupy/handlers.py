# -*- coding: utf-8 -*-

__all__ = ('set_sighandlers',)

import os
import signal

import pupy


logger = pupy.get_logger('signals')


def _defered_close_exit(connection):
    try:
        # Should be the custom event, as generated on client
        pupy.broadcast_event(0x10000000 | 0xFFFF)
    except Exception, e:
        logger.exception(e)

    logger.debug('Defered close+exit')

    pupy.client.terminate()

    if pupy.connection:
        pupy.connection.close()


def _handle_sigchld(*args, **kwargs):
    os.waitpid(-1, os.WNOHANG)


def _handle_sighup(signal, frame):
    logger.debug('SIGHUP')


def _handle_sigterm(signal, frame):
    logger.warning('SIGTERM')

    if pupy.manager:
        try:
            pupy.manager.event(pupy.Manager.TERMINATE)
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
