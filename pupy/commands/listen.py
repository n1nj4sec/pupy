# -*- encoding: utf-8 -*-

from pupylib.PupyModule import PupyArgumentParser
from pupylib.PupyOutput import Success

usage = 'start/stop/show current listeners'
parser = PupyArgumentParser(prog='listen', description=usage)
group = parser.add_mutually_exclusive_group()
group.add_argument('-l', '--list', action='store_true', help='show current listeners')
group.add_argument('-a', '--add', nargs='+', help='start listener NAME [ARGS]')
group.add_argument('-r', '--remove', type=str, help='stop listener NAME')

def do(server, handler, config, args):
    if args.add:
        name, args = args.add[0], args.add[1:]
        server.add_listener(name, ' '.join(args), motd=False)

    elif args.remove:
        server.remove_listener(args.remove)

    else:
        for listener in server.listeners.itervalues():
            handler.display(Success(listener))
