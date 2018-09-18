# -*- encoding: utf-8 -*-

from pupylib.PupyModule import PupyArgumentParser
from pupylib.PupyOutput import MultiPart, Table, Color, Line, TruncateToTerm
from pupylib.PupyCompleter import commands_completer

usage  = 'Show help'
parser = PupyArgumentParser(prog='help', description=usage)
parser.add_argument('module', nargs='?',
                    help='Show information about command', completer=commands_completer)
parser.add_argument('-M', '--modules', action='store_true',
                    help='Show information about all modules')

def do(server, handler, config, args):

    tables = []

    if args.module:
        if handler.commands.has(args.module):
            command = handler.commands.get(args.module)
            tables.append(Line(
                Color('Command:', 'yellow'),
                Color(args.module+':', 'green'),
                command.usage or 'No description'))
            if hasattr(command.parser, 'add_help'):
                tables.append(command.parser.format_help())
            else:
                parser = command.parser(server, PupyArgumentParser, config)
                tables.append(parser.parse_args(['--help']))

        for module in server.iter_modules():
            if module.get_name().lower() == args.module.lower():
                if module.__doc__:
                    doc = module.__doc__.strip()
                else:
                    doc = ''

                tables.append(Line(
                    Color('Module:', 'yellow'),
                    Color(args.module+':', 'green'),
                    doc.title().split('\n')[0]))

                if module.arg_parser.add_help:
                    tables.append(module.arg_parser.format_help())
                else:
                    tables.append(module.arg_parser.parse_args(['--help']))

                clients = server.get_clients(handler.default_filter)
                if clients:
                    ctable = []
                    for client in clients:
                        compatible = module.is_compatible_with(client)
                        ctable.append({
                            'OK': Color(
                                'Y' if compatible else 'N',
                                'green' if compatible else 'grey'
                            ),
                            'CLIENT': Color(
                                str(client),
                                'green' if compatible else 'grey'
                            )
                        })

                    tables.append(
                        Table(ctable, ['OK', 'CLIENT'], Color('Compatibility', 'yellow'), False))

        for command, alias in config.items("aliases"):
            if command == args.module:
                tables.append(Line(
                    Color('Alias:', 'yellow'),
                    Color(args.module+':', 'green'),
                    alias))

    else:
        commands = []
        for command, description in handler.commands.list():
            commands.append({
                'COMMAND': command,
                'DESCRIPTION': description
            })

        tables.append(Table(commands, ['COMMAND', 'DESCRIPTION'], Color('COMMANDS', 'yellow')))

        if args.modules:
            modules = sorted(list(server.iter_modules()), key=(lambda x:x.category))
            table = []

            for mod in modules:
                compatible = all(
                    mod.is_compatible_with(client) for client in
                    server.get_clients(handler.default_filter))

                compatible_some = any(
                    mod.is_compatible_with(client) for client in
                    server.get_clients(handler.default_filter))

                if mod.__doc__:
                    doc = mod.__doc__.strip()
                else:
                    doc = ''

                category = mod.category
                name = mod.get_name()
                brief = doc.title().split('\n')[0]

                if compatible:
                    pass
                elif compatible_some:
                    category = Color(category, 'grey')
                    name = Color(name, 'grey')
                    brief = Color(brief, 'grey')
                else:
                    category = Color(category, 'darkgrey')
                    name = Color(name, 'darkgrey')
                    brief = Color(brief, 'darkgrey')

                table.append({
                    'CATEGORY': category,
                    'NAME': name,
                    'HELP': brief
                })

            tables.append(TruncateToTerm(Table(
                table, ['CATEGORY', 'NAME', 'HELP'], Color('MODULES', 'yellow'))))

        else:
            aliased = []
            for module, description in server.get_aliased_modules():
                aliased.append({
                    'MODULE': module,
                    'DESCRIPTION': description
                })

            if aliased:
                tables.append(Table(aliased, ['MODULE', 'DESCRIPTION'], Color('ALIASED MODULES', 'yellow')))

        aliases = []
        for command, alias in config.items("aliases"):
            aliases.append({
                'ALIAS': command,
                'COMMAND': alias
            })

        if aliases:
            tables.append(Table(aliases, ['ALIAS', 'COMMAND'], Color('ALIASES', 'yellow')))

        if not args.modules:
            tables.append(Line('Use', Color('help -M', 'green'), 'command to show all available modules'))

    handler.display(MultiPart(tables))
