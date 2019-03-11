# -*- encoding: utf-8 -*-

from argparse import REMAINDER

from pupylib.PupyOutput import Table, List
from pupylib.PupyModule import config, PupyModule, PupyArgumentParser

__class_name__ = 'WMIC'

@config(category='admin', compat=['windows'])
class WMIC(PupyModule):
    ''' Query WMI using WQL '''

    dependencies = ['wql']

    @classmethod
    def init_argparse(cls):
        example = 'SELECT * FROM Win32_Share'
        cls.arg_parser = PupyArgumentParser(
            prog='wmi', description=cls.__doc__, epilog=example)
        cls.arg_parser.add_argument(
            '-c', '--columns-only', action='store_true', help='Show only column names')
        cls.arg_parser.add_argument('query', nargs=REMAINDER)

    def run(self, args):
        wql = self.client.remote('wql', 'execute_final')
        if args.query:
            cmdline = ' '.join(args.query)
        else:
            cmdline = 'SELECT DatabaseDirectory,BuildVersion,LoggingDirectory '\
              'FROM Win32_WMISetting'

        try:
            keys, columns, result = wql(cmdline)
        except Exception as e:
            self.error(e.strerror)
            return

        if args.columns_only:
            if keys:
                self.log(List(keys, caption='Keys'))

            self.log(List(columns, caption='Columns'))
            return

        values = []

        records = [{
            k:unicode(v) or '' for k,v in record
        } for record in result]

        self.log(Table(records, columns))
