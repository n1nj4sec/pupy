# -*- encoding: utf-8 -*-

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.PupyOutput import Table, TruncateToTerm
from argparse import REMAINDER

from datetime import datetime

__class_name__='IndexSearchModule'

# ZOMG Kill me please
def escape(x):
    if "'" in x:
        x = x.replace("'", "")

    return "'" + x + "'"

@config(cat='gather', compat='windows')
class IndexSearchModule(PupyModule):
    ''' Use Windows Search Index to search for data '''

    dependencies = [
        'win32com', 'win32api', 'winerror',
        'numbers', 'decimal', 'adodbapi', 'isearch'
    ]

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog='isearch', description=cls.__doc__)
        cls.arg_parser.add_argument(
            '-L', '--limit', type=int, help='Limit records (default 50)',
            default=50)
        cls.arg_parser.add_argument('-v', '--verbose', action='store_true',
                                    default=False, help='Show SQL query')
        cls.arg_parser.add_argument('-t', '--text', help='Text to search')
        cls.arg_parser.add_argument('-p', '--path', help='Path to search')
        cls.arg_parser.add_argument('-d', '--directory', help='Directory to limit output')
        cls.arg_parser.add_argument(
            '-R', '--raw', metavar='SELECT ... FROM SYSTEMINDEX ...',
            nargs=REMAINDER, help='RAW SQL Query to search '\
            '(https://docs.microsoft.com/en-us/windows/'\
            'desktop/search/-search-3x-advancedquerysyntax)')

    def run(self, args):
        query = self.client.remote('isearch', 'query')

        request = []
        if args.raw:
            request = args.raw
        else:
            request.append('SELECT TOP {} System.ItemUrl, System.Size, System.DateModified FROM SYSTEMINDEX'.format(args.limit))
            where = []
            if args.text:
                where.append('FREETEXT({})'.format(escape(args.text)))
            if args.directory:
                where.append('SCOPE={}'.format(escape('file:'+args.directory)))
            if args.path:
                where.append('CONTAINS(System.FileName, {})'.format(escape(args.path)))

            if where:
                request.append('WHERE')
                request.append('AND'.join(where))

            request.append('ORDER BY System.DateModified DESC')

        if not request:
            self.error('You should specify request')
            return

        text = ' '.join(request)

        if args.verbose:
            self.info('QUERY: {}'.format(text))

        idx, cidx, data, error = query(text, args.limit)
        if error:
            self.error(error)
        elif not data:
            self.warning('No data found')
        else:
            objects = []
            header = []
            legend = True

            if args.raw:
                legend = False
                for record in data:
                    objects.append({
                        str(idx):v for idx,v in enumerate(record)
                    })
                header = [
                    str(x) for x in xrange(cidx+1)
                ]
            else:
                header = ['File', 'Size', 'Modified']
                for record in data:
                    objects.append({
                        'File': record[0][5:] if record[0].startswith('file:') else record[0],
                        'Size': record[1],
                        'Modified': datetime.fromtimestamp(record[2])
                    })

            self.log(TruncateToTerm(Table(objects, header, legend=legend)))
