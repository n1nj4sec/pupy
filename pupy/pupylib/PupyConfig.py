# -*- coding: utf-8-*-
try:
    from ConfigParser import ConfigParser, Error, NoSectionError
except ImportError:
    from configparser import ConfigParser, Error, NoSectionError

from os import path, makedirs
from netaddr import IPAddress
import platform
import random
import string

class PupyConfig(ConfigParser):
    NoSectionError = NoSectionError

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
        self.randoms = {}
        self.command_line = {}

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

    def remove_option(self, section, key):
        if section != 'randoms':
            ConfigParser.unset(self, section, key)
        elif section in self.command_line and key in self.command_line[section]:
            del self.command_line[section][key]
            if not self.command_line[section]:
                del self.command_line[section]
        else:
            if key in self.randoms:
                del self.randoms[key]
            elif key == 'all':
                self.randoms = {}

    def set(self, section, key, value, **kwargs):
        if kwargs.get('cmd', False):
            if not section in self.command_line:
                self.command_line[section] = {}
            self.command_line[section][key] = str(value)
        elif section != 'randoms':
            if section in self.command_line and key in self.command_line[section]:
                del self.command_line[section][key]
                if not self.command_line[section]:
                    del self.command_line[section]

            ConfigParser.set(self, section, key, value)
        else:
            if not key:
                N = kwargs.get('random', 10)
                while True:
                    key = ''.join(random.choice(
                        string.ascii_letters + string.digits) for _ in range(N))

                    if not key in self.randoms:
                        break

            self.randoms[key] = value
            return key

    def get(self, *args, **kwargs):
        try:
            if args[0] == 'randoms':
                if not args[1] in self.randoms:
                    N = kwargs.get('random', 10)
                    new = kwargs.get('new', True)
                    if new:
                        self.randoms[args[1]] = ''.join(
                            random.choice(
                                string.ascii_letters + string.digits) for _ in range(N))

                return self.randoms.get(args[1], None)

            elif args[0] in self.command_line and args[1] in self.command_line[args[0]]:
                return self.command_line[args[0]][args[1]]

            return ConfigParser.get(self, *args, **kwargs)
        except Error as e:
            return None

    def getip(self, *args, **kwargs):
        ip = self.get(*args, **kwargs)
        if not ip:
            return None
        return IPAddress(ip)

    def sections(self):
        sections = ConfigParser.sections(self)
        sections.append('randoms')
        for section in self.command_line:
            if not section in sections:
                sections.append(section)

        return sections

    def options(self, section):
        if section != 'randoms':
            return ConfigParser.options(self, section)

        keys = self.randoms.keys()
        if section in self.command_line:
            for key in self.command_line[section]:
                if not key in keys:
                    keys.append(key)

        return keys
