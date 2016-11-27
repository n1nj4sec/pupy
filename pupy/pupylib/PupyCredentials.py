# -*- coding: utf-8-*-

from os import path

from network.transports import *

class Credentials(object):
    CONFIG_FILES = [
        path.join(path.dirname(__file__), '..', 'crypto', 'credentials.py'),
        path.join('crypto', 'credentials.py'),
        path.join('~', '.config', 'pupy', 'credentials.py'),
    ]

    def __init__(self):
        self._credentials = {}
        for config in self.CONFIG_FILES:
            config = path.expanduser(config)
            if path.exists(config):
                with open(config) as creds:
                    exec creds.read() in self._credentials

    def __getitem__(self, key):
        env = globals()

        if key in self._credentials:
            return self._credentials[key]
        elif key in env:
            return env[key]
        elif 'DEFAULT_{}'.format(key) in env:
            return env['DEFAULT_{}'.format(key)]
        else:
            return None

    def __setitem__(self, key, value):
        self._credentials[key] = value

    def __iter__(self):
        return iter(self._credentials)
