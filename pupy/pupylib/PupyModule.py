# -*- coding: utf-8 -*-
# --------------------------------------------------------------
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE
# --------------------------------------------------------------
import argparse
from .PupyErrors import PupyModuleExit, PupyModuleUsageError
from .PupyCompleter import PupyModCompleter, void_completer, list_completer
from .PupyConfig import PupyConfig
from .PupyOutput import (
    Text, NewLine, Error, Warn, Success,
    Info, Table, TruncateToTerm
)

from pupylib.utils.term import hint_to_text, obj2utf8
from pupylib import getLogger

import textwrap
import time
import os
import json
import re
import struct
import math
import io

REQUIRE_NOTHING  = 0
REQUIRE_STREAM   = 1
REQUIRE_REPL     = 2
REQUIRE_TERMINAL = 3

QA_STABLE = 0
QA_UNSTABLE = 1
QA_DANGEROUS = 2

logger = getLogger('module')

class IgnoreModule(Exception):
    pass

class PupyArgumentParserWrap(object):
    def __init__(self, base, wrapped):
        self.base = base
        self.wrapped = wrapped

    def __call__(self, *args, **kwargs):
        self.wrapped.__call__(*args, **kwargs)

    def __getattr__(self, name):
        BASE = self.base
        original = getattr(self.wrapped, name)

        if name in ('add_argument_group', 'add_mutually_exclusive_group'):
            def add_group(*args, **kwargs):
                group = original(*args, **kwargs)
                return PupyArgumentParserWrap(BASE, group)

            return add_group

        elif name == 'add_argument':
            def add_argument(*args, **kwargs):
                if 'completer' in kwargs:
                    completer_func = kwargs.pop('completer')
                elif 'choices' in kwargs:
                    completer_func = list_completer(kwargs['choices'])
                else:
                    completer_func = void_completer

                result = original(*args, **kwargs)

                kwargs['completer'] = completer_func
                completer = BASE.get_completer()

                for a in args:
                    if a.startswith('-'):
                        completer.add_optional_arg(a, **kwargs)
                    else:
                        completer.add_positional_arg(a, **kwargs)

                return result

            return add_argument
        else:
            return original

class PupyArgumentParserRef(argparse._ActionsContainer):
    def add_argument(self, *args, **kwargs):
        completer_func = None

        if 'completer' in kwargs:
            completer_func = kwargs.pop('completer')
        elif 'choices' in kwargs:
            completer_func = list_completer(kwargs['choices'])
        else:
            completer_func = void_completer

        arg = super(PupyArgumentParserRef, self).add_argument(*args, **kwargs)

        kwargs['completer'] = completer_func
        completer = self.get_completer()

        for a in args:
            if a.startswith('-'):
                completer.add_optional_arg(a, **kwargs)
            else:
                completer.add_positional_arg(a, **kwargs)

        return arg

    def add_argument_group(self, *args, **kwargs):
        return PupyArgumentParserWrap(
            self,
            super(PupyArgumentParserRef, self).add_argument_group(*args, **kwargs)
        )

    def add_mutually_exclusive_group(self, *args, **kwargs):
        return PupyArgumentParserWrap(
            self,
            super(PupyArgumentParserRef, self).add_mutually_exclusive_group(*args, **kwargs)
        )

    def get_completer(self):
        if hasattr(self, 'pupy_mod_completer') and self.pupy_mod_completer is not None:
            return self.pupy_mod_completer
        else:
            self.pupy_mod_completer = PupyModCompleter(self)
            return self.pupy_mod_completer

class PupyArgumentParser(argparse.ArgumentParser, PupyArgumentParserRef):
    def __init__(self, *args, **kwargs):
        if 'formatter_class' not in kwargs:
            kwargs['formatter_class'] = argparse.RawDescriptionHelpFormatter
        if 'description' in kwargs and kwargs['description']:
            kwargs['description'] = textwrap.dedent(kwargs['description'])

        argparse.ArgumentParser.__init__(self, *args, **kwargs)

    def exit(self, status=0, message=None):
        raise PupyModuleExit(message, status)

    def error(self, message):
        raise PupyModuleUsageError(self.prog, message, self.format_usage())


class Log(object):
    def __init__(self, out, log, consize, rec=None, command=None, title=None, unicode=False, stream=False):
        self.out = out
        self.log = log
        self.rec = None

        if rec in ('asciinema', 'asciinema1', 'ttyrec'):
            self.rec = rec

        self.last = 0
        self.start = 0
        self.unicode = unicode
        self.cleaner = re.compile('(\033[^m]+m)')
        self.closed = False
        self.stream = stream
        self.is_stream = self.stream

        if self.rec == 'asciinema1':
            height, width = consize
            self.log.write(
                '{{'
                '"command":{},"title":{},"env":null,"version":1,'
                '"width":{},"height":{},"stdout":['.format(
                    json.dumps(command), json.dumps(title),
                    width, height
                )
            )
            self.start = time.time()
        if self.rec == 'asciinema':
            height, width = consize
            ts = time.time()
            self.log.write(json.dumps({
                'version':2,
                'width': width,
                'height': height,
                'timestamp': ts,
                'title': title,
                'env': {
                    'SHELL': os.environ.get('SHELL'),
                    'TERM': os.environ.get('TERM'),
                }
            }))
            self.log.write('\n')
            self.last = self.start = ts
        elif self.rec == 'ttyrec':
            self.last = time.time()
        else:
            if command:
                if self.unicode:
                    command = command.decode('utf-8', errors='replace')

                self.log.write('> ' + command + '\n')

    def write(self, data):
        if self.closed:
            return

        if not data:
            return

        self.out.write(data)

        data = hint_to_text(data)
        if not self.stream:
            data += '\n'

        now = time.time()
        delay = (now - self.last) if self.last else 0
        duration = now - self.start
        self.last = now

        if self.unicode:
            if type(data) != unicode:
                data = data.decode('utf-8', errors='ignore')

        if self.rec == 'ttyrec':
            usec, sec = math.modf(now)
            usec = int(usec * 10**6)
            sec = int(sec)
            self.log.write(struct.pack('<III', sec, usec, len(data)) + data)

        elif self.rec == 'asciinema':
            self.log.write(json.dumps([
                duration, 'o', data
            ]))
            self.log.write('\n')

        elif self.rec == 'asciinema1':
            if delay:
                self.log.write(',')

            self.log.write(json.dumps([duration, data]))

        else:
            seqs = set()
            for seqgroups in self.cleaner.finditer(data):
                seqs.add(seqgroups.groups()[0])

            for seq in seqs:
                data = data.replace(seq, '')

            self.log.write(data)
            self.log.flush()

    def flush(self):
        if self.closed:
            return

        self.out.flush()
        self.log.flush()

    def close(self):
        if self.closed:
            return

        if self.rec == 'asciinema1':
            self.log.write('],"duration":{}}}'.format(
                time.time() - self.start
            ))

        self.log.close()
        self.closed = True

    def isatty(self):
        return self.out.isatty()

    def getvalue(self):
        value = self.out.getvalue()

        if not self.closed:
            self.log.flush()

        return value

    def fileno(self):
        return self.out.fileno()

    def truncate(self, size=0):
        if self.closed:
            return

        self.out.truncate(size)
        self.log.flush()

    def readline(self, size=None):
        return self.out.readline(size)

    def readlines(self, size=None):
        return self.out.readlines(size)

    def read(self, size=None):
        return self.out.read(size)


class PupyModuleMetaclass(type):
    def __init__(self, *args, **kwargs):
        super(PupyModuleMetaclass, self).__init__(*args, **kwargs)
        self.init_argparse()

class PupyModule(object):
    """
        This is the class all the pupy scripts must inherit from
        daemon_script -> script that will continue running in background once started
    """

    __metaclass__ = PupyModuleMetaclass

    # QA - Safeness of the module
    qa = QA_STABLE

    # Interaction requirements
    io = REQUIRE_NOTHING

    # if your module is meant to run in background, set this to True and override the stop_daemon method.
    daemon = False

    # if True, don't start a new module and use another instead
    unique_instance = False

    # dependencies to push on the remote target. same as calling self.client.load_package
    dependencies = []

    # Should be aliased by default
    is_module = True

    # should be changed by decorator @config
    compatible_systems = []

    # to sort modules by categories. should be changed by decorator @config
    category = "general"

    # to add search keywords. should be changed by decorator @config
    tags = []

    # stream record
    rec = None

    known_args = False
    web_handlers = []

    def __init__(self, client, job, io, log=None):
        """ client must be a PupyClient instance """
        self.client = client
        self.job = job
        self.new_deps = []
        self.log_file = log
        self.iogroup = io
        self.stdin = io.stdin
        self.stdout = io.stdout

    @classmethod
    def init_argparse(cls):
        if cls.__name__ != 'PupyModule':
            raise NotImplementedError('init_argparse() must be implemented')

    @classmethod
    def parse(cls, cmdline):
        if cls.known_args:
            args, unknown_args = cls.arg_parser.parse_known_args(cmdline)
            args.unknown_args = unknown_args
            return args
        else:
            args = cls.arg_parser.parse_args(cmdline)

        args.original_cmdline = cmdline
        return args

    def init(self, args):
        self.iogroup.set_title(self)

        if self.client and (self.config.getboolean('pupyd', 'logs') or self.log_file):
            replacements = {
                '%c': self.client.short_name(),
                '%m': self.client.desc['macaddr'],
                '%M': self.get_name(),
                '%p': self.client.desc['platform'],
                '%a': self.client.desc['address'],
                '%h': self.client.desc['hostname'],
                '%u': self.client.desc['user'],
                '%t': time.time(),
            }

            if self.log_file:
                for k,v in replacements.iteritems():
                    log = self.log_file.replace(k, str(v))
            else:
                log = self.config.get_file('logs', replacements)

            if self.rec:
                log = open(log, 'w+')
                unicode = False
            else:
                log = io.open(log, 'w+', encoding='utf8')
                unicode = True

            self.stdout = Log(
                self.stdout,
                log,
                self.iogroup.consize,
                rec=self.rec,
                command=self.get_name() + ' ' + u' '.join(args.original_cmdline),
                unicode=unicode,
                stream=self.io != REQUIRE_NOTHING
            )

    @property
    def config(self):
        try:
            return self.job.pupsrv.config
        except:
            return PupyConfig()

    @classmethod
    def get_name(cls):
        return cls.__module__

    def import_dependencies(self):
        if type(self.dependencies) == dict:
            dependencies = self.dependencies.get(self.client.platform, []) + (
                self.dependencies.get('posix', []) if self.client.is_posix() else []
            ) + self.dependencies.get('all', [])
        else:
            dependencies = self.dependencies

        if self.client:
            self.client.load_package(dependencies, new_deps=self.new_deps)

    def clean_dependencies(self):
        for d in self.new_deps:
            try:
                self.client.unload_package(d)
            except Exception, e:
                logger.exception('Dependency unloading failed: %s', e)

    def start_webplugin(self):
        if not self.client.pupsrv.start_webserver():
            return None
        else:
            return self.client.pupsrv.pupweb.start_webplugin('rdesktop', self.web_handlers)

    @classmethod
    def is_compatible_with(cls, client):
        if 'all' in cls.compatible_systems or len(cls.compatible_systems) == 0:
            return True
        elif 'android' in cls.compatible_systems and client.is_android():
            return True
        elif 'windows' in cls.compatible_systems and client.is_windows():
            return True
        elif 'linux' in cls.compatible_systems and client.is_linux():
            return True
        elif 'solaris' in cls.compatible_systems and client.is_solaris():
            return True
        elif ('darwin' in cls.compatible_systems or 'osx' in cls.compatible_systems) and client.is_darwin():
            return True
        elif 'unix' in cls.compatible_systems and client.is_unix():
            return True
        elif 'posix'in cls.compatible_systems and client.is_posix():
            return True

        return False

    def is_compatible(self):
        """ override this method to define if the script is compatible with the givent client. The first value of the returned tuple is True if the module is compatible with the client and the second is a string explaining why in case of incompatibility"""
        if not self.is_compatible_with(self.client):
            return (False, 'This module currently only support the following systems: %s'%(
            ','.join(self.compatible_systems)))
        else:
            return True, ''

    def is_daemon(self):
        return self.daemon

    def stop_daemon(self):
        """ override this method to define how to stop your module if the module is a deamon or is launch as a job """
        pass

    def run(self, args):
        """
            the parameter args is an object as returned by the parse_args() method from argparse. You can define your arguments options in the init_argparse() method
            The run method does not return any argument. You can raise PupyModuleError in case of error
            NOTICE: DO NOT use print in this function, always use self.rawlog, self.log, self.error and self.warning instead
        """
        raise NotImplementedError("PupyModule's run method has not been implemented !")

    def encode(self, msg):
        tmsg = type(msg)
        if issubclass(tmsg, Text) or tmsg == unicode:
            return msg
        elif tmsg == str:
            return msg.decode('utf8', errors="replace")
        else:
            return obj2utf8(msg)

    def _message(self, msg):
        if self.io in (REQUIRE_REPL, REQUIRE_TERMINAL):
            msg = self.iogroup.as_text(msg)

        self.stdout.write(msg)

        if self.io != REQUIRE_NOTHING:
            self.stdout.write(self.iogroup.as_text(NewLine()))

    def rawlog(self, msg):
        """ log data to the module stdout """
        self._message(self.encode(msg))

    def log(self, msg):
        self._message(self.encode(msg))

    def error(self, msg, extended=False):
        self._message(self.encode(Error(msg)))

    def warning(self, msg):
        self._message(self.encode(Warn(msg)))

    def success(self, msg):
        self._message(self.encode(Success(msg)))

    def info(self, msg):
        self._message(self.encode(Info(msg)))

    def newline(self, lines=1):
        self._message(NewLine(lines))

    def table(self, data, header=None, caption=None, truncate=False, legend=True, vspace=0):
        data = Table(data, header, caption, legend, vspace)
        if truncate:
            data = TruncateToTerm(data)
        self._message(data)

    def closeio(self):
        if isinstance(self.stdout, Log):
            self.stdout.close()

        self.iogroup.close()

def config(**kwargs):
    for l in ['compat', 'compatibilities', 'compatibility', 'tags']:
        if l in kwargs:
            if type(kwargs[l])!=list:
                kwargs[l]=[kwargs[l]]

    def class_rebuilder(klass):
        klass.tags = kwargs.get('tags', klass.tags)
        klass.category = kwargs.get('category', kwargs.get('cat', klass.category))
        klass.compatible_systems = kwargs.get(
            'compatibilities',
            kwargs.get('compatibility',
                       kwargs.get('compat',klass.compatible_systems)))
        klass.daemon = kwargs.get('daemon', klass.daemon)

        return klass

    for k in kwargs.iterkeys():
        if k not in ['tags', 'category', 'cat', 'compatibilities', 'compatibility', 'compat', 'daemon']:
            logger.warning("Unknown argument \"%s\" to @config context manager"%k)

    return class_rebuilder
