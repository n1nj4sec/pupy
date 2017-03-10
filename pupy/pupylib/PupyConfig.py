# -*- coding: utf-8-*-
try:
    from ConfigParser import ConfigParser, Error
except ImportError:
    from configparser import ConfigParser, Error

from os import path, makedirs
from netaddr import IPAddress
import platform

class PupyConfig(ConfigParser):
    def __init__(self, config='pupy.conf'):
        self.root = path.abspath(path.join(path.dirname(__file__), '..'))
        self.user_root = path.expanduser(path.join('~', '.config', 'pupy'))
        self.project_path = path.join('config', config)
        self.user_path = path.join(self.user_root, config)
        self.files = [
            path.join(self.root, config+'.default'),
            path.join(self.root, config),
            self.user_path,
            self.project_path,
            config
        ]

        ConfigParser.__init__(self)
        self.read(self.files)

    def save(self, project=True, user=False):
        if project:
            project_dir = path.dirname(self.project_path)
            if not path.isdir(project_dir):
                makedirs(project_dir)

            with open(self.project_path, 'w') as config:
                self.write(config)

        if user:
            user_dir = path.dirname(self.user_path)
            if not path.isdir(user_dir):
                makedirs(user_dir)

            with open(self.user_path, 'w') as config:
                self.write(config)

    def get_folder(self, folder='data', substitutions={}, create=True):
        prefer_workdir = self.getboolean('paths', 'prefer_workdir')
        from_config = self.get('paths', folder)

        retfolder = ''
        if from_config:
            retfolder = from_config
        elif path.isabs(folder):
            retfolder = folder
        elif prefer_workdir:
            retfolder = folder
        else:
            retfolder = path.join(self.user_root, folder)

        for key, value in substitutions.iteritems():
            value = value.replace('/', '_').replace('..', '_')
            if platform.system == 'Windows':
                value = value.replace(':', '_')
            retfolder = retfolder.replace(key, value)

        if path.isdir(retfolder):
            return path.abspath(retfolder)
        elif path.exists(retfolder):
            raise ValueError('{} is not a folder'.format(retfolder))
        elif create:
            makedirs(retfolder)
            return path.abspath(retfolder)
        else:
            return path.abspath(retfolder)

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
