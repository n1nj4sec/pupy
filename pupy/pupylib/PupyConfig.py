# -*- coding: utf-8-*-
try:
    from ConfigParser import ConfigParser, Error
except ImportError:
    from configparser import ConfigParser, Error

from os import path
from netaddr import IPAddress

class PupyConfig(ConfigParser):
    def __init__(self, config='pupy.conf'):
        self.root = path.abspath(path.join(path.dirname(__file__), '..'))
        self.files = [
            path.join(self.root, config+'.default'),
            path.join(self.root, config),
            path.expandvars(path.expanduser(path.join('~', '.config', 'pupy', config))),
            config
        ]

        ConfigParser.__init__(self)
        self.read(self.files)

    def get(self, *args, **kwargs):
        try:
            return ConfigParser.get(self, *args, **kwargs)
        except Error as e:
            return None

    def getip(self, *args, **kwargs):
        ip = self.get(*args, **kwargs)
        if not ip:
            return None
        return IPAddress(ip)
