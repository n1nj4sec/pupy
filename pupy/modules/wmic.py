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
            columns, result = wql(cmdline)
        except Exception as e:
            self.error(e.strerror)
            return

        if args.columns_only:
            self.log(List(columns, caption='Columns'))
            return

        if len(columns) == 1:
            records = []
            for record in result:
                for item in record:
                    if item[0] == columns[0]:
                        records.append(item[1])
            self.log(List(records, caption=columns[0]))
        else:
            records = [{
                k:v or '' for k,v in record
            } for record in result]

            self.log(Table(records, columns))
