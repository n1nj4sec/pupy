# -*- encoding: utf-8 -*-

__all__ = ('InvalidCommand', 'Commands')

import os
import imp
import shlex

from pupylib.PupyCompleter import commands_completer
from pupylib.PupyModule import PupyArgumentParser

class InvalidCommand(Exception):
    pass

class CommandsNamespace(object):

    __slots__ = ('module', 'args')

    def __init__(self, module, args):
        self.module = module
        self.args = args

class Commands(object):
    SUFFIXES = tuple([
        suffix for suffix, _, rtype in imp.get_suffixes() \
        if rtype == imp.PY_SOURCE
    ])

    def __init__(self):
        self._commands = {}
        self._commands_stats = {}
        self._refresh()

    def _refresh(self):
        commands_paths = [
            os.path.dirname(__file__)
        ]

        files = {}

        for path in commands_paths:
            files.update({
                '.'.join(x.rsplit('.', 1)[:-1]):os.path.join(path, x) \
                for x in os.listdir(path) if x.endswith(self.SUFFIXES) and \
                not x.startswith('__init__')
            })

        for command, source in files.iteritems():
            try:
                current_stat = os.stat(source)
            except OSError:
                continue

            if command not in self._commands or self._commands_stats[command] != current_stat.st_mtime:
                try:
                    self._commands[command] = imp.load_source(command, source)
                    self._commands_stats[command] = current_stat.st_mtime
                except IOError:
                    pass

    def _get_command(self, cmdline, aliases, modules, refresh=True):
        argv = shlex.split(cmdline)
        if not argv:
            raise InvalidCommand(cmdline)

        argv0 = argv[0]
        args = []

        if len(argv) > 1:
            args = argv[1:]

        if argv0 in aliases:
            aliased = aliases[argv0]
            if '{' in aliased or '%' in aliased:
                cmdline = shlex.split(aliased.format(args))
                argv0, args = argv[0], argv[1:]
            else:
                aargv = shlex.split(aliased)
                argv0, args = aargv[0], aargv[1:] + args

        if argv0 not in self._commands and refresh:
            self._refresh()

        if argv0 not in self._commands:
            found = False
            for module in modules:
                if argv0 == module.get_name():
                    args.insert(0, argv0)
                    argv0 = 'run'
                    found = True
                    break

            if not found:
                raise InvalidCommand(argv0)

        return self._commands[argv0], args

    def has(self, command):
        if command not in self._commands:
            self._refresh()

        return command in self._commands

    def get(self, command):
        if command not in self._commands:
            self._refresh()

        return self._commands.get(command)

    def execute(self, server, handler, config, cmdline, clients_filter=None):
        aliases = dict(config.items('aliases'))
        command, args = self._get_command(
            cmdline, aliases, server.iter_modules(
                by_clients=True,
                clients_filter=clients_filter or handler.default_filter
            ))

        parser = command.parser
        if callable(parser):
            parser = parser(server, handler, config)

        parsed_args = parser.parse_args(args)

        old_filter = handler.default_filter

        if clients_filter:
            handler.default_filter = clients_filter

        try:
            command.do(server, handler, config, parsed_args)
        finally:
            if clients_filter and handler.default_filter == clients_filter:
                handler.default_filter = old_filter

    def list(self, refresh=True):
        if refresh:
            self._refresh()

        for command, module in self._commands.iteritems():
            yield command, module.usage

    def completer(self, context, cmdline):
        server, handler, config = context.server, context.handler, context.config

        aliases = dict(config.items('aliases'))
        modules = list(server.iter_modules(
            by_clients=True,
            clients_filter=handler.default_filter))

        try:
            command, args = self._get_command(cmdline, aliases, modules, False)
            parser = None
            if hasattr(command.parser, 'add_help'):
                parser = command.parser
            else:
                parser = command.parser(server, PupyArgumentParser, config)

            completer = parser.get_completer()

            return completer.complete, command.__name__, args

        except InvalidCommand:
            return commands_completer, '', ''
