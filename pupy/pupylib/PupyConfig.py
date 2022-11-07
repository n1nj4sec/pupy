# -*- coding: utf-8-*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

__all__ = [
    'Tags', 'PupyConfig', 'Error', 'NoSectionError'
]

try:
    from ConfigParser import (
        RawConfigParser, Error, NoSectionError, NoOptionError
    )

    setattr(RawConfigParser, 'read_file', RawConfigParser.readfp)
except ImportError:
    from configparser import (
        RawConfigParser, Error, NoSectionError, NoOptionError
    )

from os import path, makedirs
from netaddr import IPAddress

import sys
import platform
import random
import string
import datetime
import errno
import shutil
import os

from pupy.network.lib.convcompat import (
    as_unicode_string, as_native_string
)

from .PupyLogger import getLogger
from pupy.pupylib import ROOT
logger = getLogger('config')

if sys.version_info.major > 2:
    long = int
    xrange = range


TAGS_SECTION = as_native_string('tags')
PATHS_SECTION = as_native_string('paths')


class Tags(object):
    def __init__(self, config, node):
        self.config = config
        self.node = as_native_string(node)

    def __iter__(self):
        for item in self.get():
            yield as_unicode_string(item)

    def get(self):
        tags = self.config.get(TAGS_SECTION, self.node)
        if not tags:
            return set()

        return set(
            as_unicode_string(tag) for tag in tags.split(',')
        )

    def set(self, tags):
        encoded_tags = as_native_string(
            ','.join([
                as_unicode_string(x, fail='convert') for x in tags
            ])
        )

        return self.config.set(TAGS_SECTION, self.node, encoded_tags)

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
        self.config.remove_option(TAGS_SECTION, self.node)

    def __str__(self):
        return as_native_string(','.join(self.get()))


class PupyConfig(RawConfigParser):

    def __init__(self, config='pupy.conf'):
        self.root = path.abspath(ROOT)
        self.user_root = path.expanduser(path.join('~', '.pupy'))
        self.default_file = path.join(self.root, "conf", config+'.default')
        self.user_path = path.join(self.user_root, config)

        prefer_workdir = self.getboolean(PATHS_SECTION, 'prefer_workdir')
        if not prefer_workdir:
            if not os.path.exists(self.user_root):
                os.makedirs(self.user_root)
            if not os.path.exists(self.user_path):
                shutil.copyfile(self.default_file, self.user_path)
                logger.info("No default pupy config file, creating one in {}".format(self.user_path))

        self.files = [
            self.default_file,
            self.user_path
        ]
        self.randoms = {}
        self.command_line = {}

        RawConfigParser.__init__(self)

        for file in self.files:
            try:
                self.read_file(open(file, 'r'))

                logger.info(
                    'Loaded config data from %s', file
                )
            except (IOError, OSError) as e:
                if e.errno == errno.EEXIST:
                    pass

    def tags(self, node):
        if type(node) in (int, long):
            node = '{:012x}'.format(node)

        return Tags(self, node)

    def by_tags(self, tags):
        available_tags = {
            as_unicode_string(k): tuple([
                as_unicode_string(tag)
                for tag in self.get('tags', k).split(',')
            ]) for k in self.options('tags')
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

        for node in available_tags:
            node_tags = available_tags[node]
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

            logger.info('Config saved to %s', self.project_path)

        if user:
            user_dir = path.dirname(self.user_path)
            if not path.isdir(user_dir):
                makedirs(user_dir)

            with open(self.user_path, 'w') as config:
                self.write(config)

            logger.info('Config saved to %s', self.user_path)

    def get_path(self, filepath, substitutions={}, create=True, dir=False):
        prefer_workdir = self.getboolean(PATHS_SECTION, 'prefer_workdir')
        from_config = self.get(PATHS_SECTION, filepath)

        if from_config:
            filepath = as_unicode_string(from_config)

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
            '%t': as_unicode_string(
                datetime.datetime.now(), fail='convert'
            ).replace(' ', '_').replace(':', '-')
        })

        for key in substitutions:
            value = substitutions[key]
            try:
                value = value.replace('/', '_').replace('..', '_')
                if platform.system == 'Windows':
                    value = value.replace(':', '_')
            except Exception:
                pass

            retfilepath = retfilepath.replace(
                key, as_unicode_string(value, fail='convert')
            )

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
            RawConfigParser.remove_option(
                self,
                as_native_string(section),
                as_native_string(key)
            )

        elif section in self.command_line and \
                key in self.command_line[section]:
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
            section = as_native_string(section)
            key = as_native_string(key)

            if section in self.command_line and \
                    key in self.command_line[section]:
                del self.command_line[section][key]
                if not self.command_line[section]:
                    del self.command_line[section]

            try:
                RawConfigParser.set(self, section, key, value)
            except NoSectionError:
                logger.debug('Create new section {}'.format(section))
                RawConfigParser.add_section(self, section)
                RawConfigParser.set(self, section, key, value)

        else:
            if not key:
                N = kwargs.get('random', 10)
                while True:
                    key = ''.join(
                        random.choice(
                            string.ascii_letters + string.digits
                        ) for _ in range(N)
                    )

                    if key not in self.randoms:
                        break

            self.randoms[key] = value
            return key

    def getboolean(self, section, option, default=False):
        section = as_native_string(section)
        option = as_native_string(option)

        try:
            result = RawConfigParser.getboolean(self, section, option)

            if result is None:
                return default

            return result
        except AttributeError:
            return default

    def get(
        self, section, option, default=None,
            random=10, new=True, **kwargs):
        try:
            if section == 'randoms':
                if option not in self.randoms:
                    if new:
                        self.randoms[option] = ''.join(
                            random.choice(
                                string.ascii_letters + string.digits
                            ) for _ in xrange(random)
                        )

                return self.randoms.get(option, None)

            elif section in self.command_line and \
                    option in self.command_line[section]:
                return self.command_line[section][option]

            section = as_native_string(section)
            option = as_native_string(option)
            result = as_unicode_string(
                RawConfigParser.get(self, section, option, **kwargs),
                fail=False
            )

            if result is None:
                return default

            return result

        except (NoSectionError, NoOptionError):
            return default

    def getip(self, section, option, default=None):
        ip = self.get(section, option)
        if not ip:
            return default

        return IPAddress(ip)

    def sections(self):
        sections = [
            as_unicode_string(section)
            for section in RawConfigParser.sections(self)
        ]

        sections.append('randoms')
        for section in self.command_line:
            if section not in sections:
                sections.append(section)

        return sections

    def options(self, section):
        if section != 'randoms':
            return [
                as_unicode_string(option)
                for option in RawConfigParser.options(
                    self, as_native_string(section)
                )
            ]

        keys = self.randoms.keys()
        if section in self.command_line:
            for key in self.command_line[section]:
                if key not in keys:
                    keys.append(key)

        return keys
