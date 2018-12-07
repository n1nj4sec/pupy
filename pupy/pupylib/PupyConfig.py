# -*- coding: utf-8-*-

__all__ = [
    'Tags', 'PupyConfig', 'Error', 'NoSectionError'
]

try:
    from ConfigParser import ConfigParser, Error, NoSectionError
except ImportError:
    from configparser import ConfigParser, Error, NoSectionError

from os import path, makedirs
from netaddr import IPAddress
import platform
import random
import string
import datetime

from .PupyLogger import getLogger
logger = getLogger('config')

class Tags(object):
    def __init__(self, config, node):
        self.config = config
        self.node = node

    def __iter__(self):
        return iter(self.get())

    def get(self):
        try:
            return set(self.config.get('tags', self.node).split(','))
        except:
            return set()

    def set(self, tags):
        return self.config.set('tags', self.node, ','.join([
            str(x) for x in tags
        ]))

    def add(self, *tags):
        current_tags = self.get()
        for tag in tags:
            current_tags.add(tag)
        self.set(current_tags)

    def remove(self, *tags):
        current_tags = self.get()
        for tag in tags:
            if tag in current_tags:
                current_tags.remove(tag)

        if current_tags:
            self.set(current_tags)
        else:
            self.clear()

    def clear(self):
        self.config.remove_option('tags', self.node)

    def __str__(self):
        return ','.join(self.get())

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

        logger.debug('Loading config from {}'.format(':'.join(self.files)))

        self.read(self.files)

    def tags(self, node):
        if type(node) in (int, long):
            node = '{:012x}'.format(node)

        return Tags(self, node)

    def by_tags(self, tags):
        available_tags = {
            k:self.get('tags', k).split(',') for k in self.options('tags')
        }

        if '&' in tags:
            tags = tags.split('&')
            op_filter = all
        elif '|' in tags:
            tags = tags.split('|')
            op_filter = any
        else:
            tags = tags.split(',')
            op_filter = any

        result = []

        for node, node_tags in available_tags.iteritems():
            if op_filter(x in node_tags for x in tags):
                result.append(node)

        return result

    def save(self, project=True, user=False):
        if project:
            project_dir = path.dirname(self.project_path)
            if not path.isdir(project_dir):
                makedirs(project_dir)

            with open(self.project_path, 'w') as config:
                self.write(config)

            logger.debug('Config saved to {}'.format(self.project_path))

        if user:
            user_dir = path.dirname(self.user_path)
            if not path.isdir(user_dir):
                makedirs(user_dir)

            with open(self.user_path, 'w') as config:
                self.write(config)

            logger.debug('Config saved to {}'.format(self.user_path))

    def get_path(self, filepath, substitutions={}, create=True, dir=False):
        prefer_workdir = self.getboolean('paths', 'prefer_workdir')
        from_config = self.get('paths', filepath)

        if from_config:
            filepath = from_config

        retfilepath = ''

        # 1. If path is absolute filepath use as-is
        if path.isabs(filepath):
            retfilepath = filepath

        # 2. If file exists in workdir then use it
        elif path.exists(filepath):
            retfilepath = filepath

        # 3. If file exists in userdir then use it
        elif path.exists(path.join(self.user_root, filepath)):
            retfilepath = path.join(self.user_root, filepath)

        # 4. If file exists in root dir, and we are not going to
        #    create something new (default) then use it
        elif path.exists(path.join(self.root, filepath)) and not create:
            retfilepath = path.join(self.root, filepath)

        # 5. File/path is not exists. We need to create one
        else:
            if prefer_workdir:
                retfilepath = filepath
            else:
                retfilepath = path.join(self.user_root, filepath)

        substitutions.update({
            '%t': str(datetime.datetime.now()).replace(' ','_').replace(':','-')
        })

        for key, value in substitutions.iteritems():
            try:
                value = value.replace('/', '_').replace('..', '_')
                if platform.system == 'Windows':
                    value = value.replace(':', '_')
            except:
                pass

            retfilepath = retfilepath.replace(key, str(value))

        if dir and path.isdir(retfilepath):
            return path.abspath(retfilepath)
        elif not dir and path.isfile(retfilepath):
            return path.abspath(retfilepath)
        elif path.exists(retfilepath):
            raise ValueError('{} is not a {}'.format(
                path.abspath(retfilepath),
                'dir' if dir else 'file'))
        elif create:
            if dir:
                makedirs(retfilepath)
            else:
                dirpath = path.dirname(retfilepath)
                if not path.isdir(dirpath):
                    makedirs(dirpath)

            return path.abspath(retfilepath)
        else:
            return path.abspath(retfilepath)

    def get_folder(self, folder='data', substitutions={}, create=True):
        return self.get_path(folder, substitutions, create, True)

    def get_file(self, folder='data', substitutions={}, create=True):
        return self.get_path(folder, substitutions, create)

    def remove_option(self, section, key):
        if section != 'randoms':
            ConfigParser.remove_option(self, section, key)

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
            if section not in self.command_line:
                self.command_line[section] = {}
            self.command_line[section][key] = str(value)
        elif section != 'randoms':
            if section in self.command_line and key in self.command_line[section]:
                del self.command_line[section][key]
                if not self.command_line[section]:
                    del self.command_line[section]

            try:
                ConfigParser.set(self, section, key, value)
            except NoSectionError:
                logger.debug('Create new section {}'.format(section))
                ConfigParser.add_section(self, section)
                ConfigParser.set(self, section, key, value)

        else:
            if not key:
                N = kwargs.get('random', 10)
                while True:
                    key = ''.join(random.choice(
                        string.ascii_letters + string.digits) for _ in range(N))

                    if key not in self.randoms:
                        break

            self.randoms[key] = value
            return key

    def getboolean(self, *args, **kwargs):
        try:
            return ConfigParser.getboolean(self, *args, **kwargs)
        except AttributeError:
            return False

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
        except:
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
            if section not in sections:
                sections.append(section)

        return sections

    def options(self, section):
        if section != 'randoms':
            return ConfigParser.options(self, section)

        keys = self.randoms.keys()
        if section in self.command_line:
            for key in self.command_line[section]:
                if key not in keys:
                    keys.append(key)

        return keys
