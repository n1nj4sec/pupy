# -*- encoding: utf-8 -*-

from pupylib.PupyModule import PupyArgumentParser
from pupylib.PupyOutput import Table

usage  = 'Show help'
parser = PupyArgumentParser(prog='help', description=usage)
parser.add_argument('module', nargs='?', help='Show information about command')

def do(server, handler, config, args):
    output = []

    if args.module:
        if handler.commands.has(args.module):
            output.append({
                'COMMAND': args.module,
                'DESCRIPTION': handler.commands.get(args.module).usage or ''
            })
    else:
        for command, description in handler.commands.list():
            output.append({
                'COMMAND': command,
                'DESCRIPTION': description
            })

    handler.display(Table(output, ['COMMAND', 'DESCRIPTION']))
