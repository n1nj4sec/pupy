# -*- encoding: utf-8 -*-

from pupylib.PupyModule import PupyArgumentParser
from pupylib.PupyOutput import Table

usage  = "List available modules with a brief description (the first description line)"
parser = PupyArgumentParser(prog='modules', description=usage)

def do(server, handler, config, args):
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

    handler.display(Table(table, ['CATEGORY', 'NAME', 'HELP'], caption))
