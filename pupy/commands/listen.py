# -*- encoding: utf-8 -*-

from pupylib.PupyModule import PupyArgumentParser
from pupylib.PupyOutput import Success, Color, Table

from network.conf import transports

usage = 'start/stop/show current listeners'
parser = PupyArgumentParser(prog='listen', description=usage)
group = parser.add_mutually_exclusive_group()
group.add_argument('-l', '--list', action='store_true', help='show current listeners')
group.add_argument('-L', '--list-transports', action='store_true', help='show available transports')
group.add_argument(
    '-a', '--add', nargs='+',
    metavar=('TRANSPORT', 'TRANSPORT_ARG1'), help='start listener')
group.add_argument(
    '-A', '--add-no-pproxy', nargs='+',
    metavar=('TRANSPORT', 'TRANSPORT_ARG1'), help='start listener (ignore pproxy)')
group.add_argument(
    '-r', '--remove', metavar='TRANSPORT',
    type=str, help='stop listener')

def do(server, handler, config, args):
    if args.add:
        name, args = args.add[0], args.add[1:]
        server.add_listener(name, ' '.join(args), motd=False)
    elif args.add_no_pproxy:
        name, args = args.add_no_pproxy[0], args.add_no_pproxy[1:]
        server.add_listener(
            name, ' '.join(args), motd=False, ignore_pproxy=True)
    elif args.remove:
        server.remove_listener(args.remove)

    elif args.list_transports:

        table = []

        for name, transport in transports.iteritems():
            color = None
            listener = None
            info = transport.info

            if name in server.listeners:
                color = 'lightgreen'
                listener = Color(str(server.listeners[name]), color)
                name = Color(name, color)
                info = Color(info, color)

            table.append({
                'NAME': name,
                'INFO': info,
                'ACTIVE': listener
            })

        handler.display(Table(table, ['NAME', 'INFO', 'ACTIVE']))

    else:
        for listener in server.listeners.itervalues():
            handler.display(Success(listener))
