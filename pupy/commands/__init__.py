# -*- encoding: utf-8 -*-

__all__ = ( 'InvalidCommand', 'Commands' )

import os
import imp
import shlex

class InvalidCommand(Exception):
    pass

class Commands(object):
    SUFFIXES = tuple([
        suffix for suffix, _, rtype in imp.get_suffixes() \
        if rtype == imp.PY_SOURCE
    ])

    def __init__(self):
        self._commands = {}
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

        for command,source in files.iteritems():
            if not command in self._commands or self._commands[command].__file__ != source:
                self._commands[command] = imp.load_source(command, source)
            else:
                self._commands[command] = reload(command, source)

    def _get_command(self, cmdline, aliases, modules):
        argv = shlex.split(cmdline)
        argv0, args = argv[0], argv[1:]

        if argv0 in aliases:
            aliased = aliases[argv0]
            if '{' in aliased or '%' in aliased:
                cmdline = shlex.split(aliased.format(args))
                argv0, args = argv[0], argv[1:]
            else:
                aargv = shlex.split(aliased)
                argv0, args = aargv[0], aargv[1:] + args

            if argv0 not in self._commands:
                self._refresh()

            if not argv0 in self._commands:
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

        else:
            if not argv0 in self._commands:
                self._refresh()

        if not argv0 in self._commands:
            raise InvalidCommand(argv0)

        command = self._commands[argv0]

        return command, args

    def has(self, command):
        if not command in self._commands:
            self._refresh()

        return command in self._commands

    def get(self, command):
        if not command in self._commands:
            self._refresh()

        return self._command.get(command)

    def execute(self, server, handler, config, cmdline):
        aliases = {}
        if config:
            aliases = dict(config.items('aliases'))

        command, args = self._get_command(
            cmdline, aliases, server.iter_modules())

        parser = command.parser
        if callable(parser):
            parser = parser(server, handler, config)

        parsed_args = parser.parse_args(args)
        command.do(server, handler, config, parsed_args)

    def list(self):
        self._refresh()

        for command, module in self._commands.iteritems():
            yield command, module.usage
