# -*- encoding: utf-8 -*-

from pupylib.PupyModule import PupyArgumentParser
from pupylib.PupyOutput import Table

usage  = "Assign tag to current session"

parser = PupyArgumentParser(prog='tag', description=usage)
parser.add_argument('-a', '--add', metavar='tag', nargs='+', help='Add tags')
parser.add_argument('-r', '--remove', metavar='tag', nargs='+', help='Remove tags')
parser.add_argument('-w', '--write-project', action='store_true',
                        default=False, help='save config to project folder')
parser.add_argument('-W', '--write-user', action='store_true',
                        default=False, help='save config to user folder')

def do(server, handler, config, modargs):
    data = []

    clients = server.get_clients(handler.default_filter)

    if not clients:
        return

    for client in clients:
        tags = config.tags(client.node())

        if modargs.remove:
            tags.remove(*modargs.remove)

        if modargs.add:
            tags.add(*modargs.add)

        data.append({
            'ID': client.node(),
            'TAGS': tags
        })

    config.save(
        project=modargs.write_project,
        user=modargs.write_user
    )

    handler.display(Table(data))
