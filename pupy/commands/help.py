# -*- encoding: utf-8 -*-

from pupylib.PupyModule import PupyArgumentParser
from pupylib.PupyOutput import NewLine, MultiPart, Table, Color, Line, TruncateToTerm

usage  = 'Show help'
parser = PupyArgumentParser(prog='help', description=usage)
parser.add_argument('module', nargs='?', help='Show information about command')
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
            tables.append(command.parser.format_help())

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
                tables.append(module.arg_parser.format_help())

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
            system = ''
            caption = ''
            if handler.default_filter:
                system = server.get_clients(handler.default_filter)[0].desc['platform'].lower()
                caption = 'Compatible with {}'.format(system)

            modules = sorted(list(server.iter_modules()), key=(lambda x:x.category))
            table = []

            for mod in modules:
                compatible = handler.default_filter and (
                    system in mod.compatible_systems or not mod.compatible_systems
                ) or not handler.default_filter

                if compatible:
                    if mod.__doc__:
                        doc = mod.__doc__.strip()
                    else:
                        doc = ''

                    table.append({
                        'CATEGORY': mod.category,
                        'NAME': mod.get_name(),
                        'HELP': doc.title().split('\n')[0]
                    })

            tables.append(TruncateToTerm(Table(
                table, ['CATEGORY', 'NAME', 'HELP'], Color(caption or 'MODULES', 'yellow'))))

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
