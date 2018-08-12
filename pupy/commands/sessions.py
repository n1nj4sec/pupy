# -*- encoding: utf-8 -*-

from pupylib.PupyModule import PupyArgumentParser
from pupylib.PupyOutput import Color, Success, Table

usage  = 'list/interact with established sessions'
parser = PupyArgumentParser(prog='sessions', description=usage)
parser.add_argument('-i', '--interact', metavar='<filter>',
                    help="change the default --filter value for other commands")
parser.add_argument('-g', '--global-reset', action='store_true',
                    help="reset --interact to the default global behavior")
parser.add_argument('-k', dest='kill', metavar='<id>', type=int, help='Kill the selected session')
parser.add_argument('-K', dest='killall', action='store_true', help='Kill all sessions')
parser.add_argument('-d', dest='drop', metavar='<id>', type=int,
                    help='Drop the connection (abruptly close the socket)')
parser.add_argument('-D', dest='dropall', action='store_true', help='Drop all connections')

def do(server, handler, config, modargs):
    if modargs.global_reset:
        handler.default_filter = None
        handler.display(Success('Default filter reset to global'))

    elif modargs.interact:
        handler.default_filter = modargs.interact
        handler.display(Success('Default filter set to {}'.format(
            handler.default_filter)))

    elif modargs.kill:
        selected_client = server.get_clients(modargs.kill)
        if selected_client:
            try:
                selected_client[0].conn.exit()
            except Exception:
                pass

    elif modargs.drop:
        selected_client = server.get_clients(modargs.drop)
        if selected_client:
            try:
                selected_client[0].conn._conn.close()
            except Exception:
                pass

    elif modargs.dropall:
        clients = list(server.get_clients_list())
        for client in clients:
            try:
                client.conn._conn.close()
            except Exception:
                pass

    elif modargs.killall:
        clients = server.get_clients_list()
        descriptions = [
            x.desc for x in clients
        ]

        for description in descriptions:
            try:
                server.get_clients(description['id'])[0].conn.exit()
            except Exception:
                pass
    else:
        client_list = server.get_clients_list()

        if handler.default_filter:
            filtered_clients = server.get_clients(handler.default_filter)
        else:
            filtered_clients = client_list

        columns = [
            'id', 'user', 'hostname', 'platform', 'release', 'os_arch',
            'proc_arch', 'intgty_lvl', 'address', 'tags'
        ]

        content = []

        for client in client_list:
            color = 'white' if client in filtered_clients else 'darkgrey'

            data = {
                k:Color(v, color)
                for k,v in client.desc.iteritems() if k in columns
            }

            data.update({
                'tags': Color(config.tags(client.node()), color)
            })

            content.append(data)

        handler.display(Table(content, columns))
