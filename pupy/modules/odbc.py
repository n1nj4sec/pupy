# -*- encoding: utf-8 -*-

from argparse import REMAINDER
from threading import Event
from re import compile as re_compile
from re import IGNORECASE
from os.path import join, dirname
from hashlib import md5
from datetime import datetime
from io import open

from pupylib.PupyOutput import Table, List, NewLine
from pupylib.PupyModule import (
    config, PupyModule, PupyArgumentParser, PupyConfig
)

__class_name__ = 'ODBC'

END = 0
HEADER = 1
DATA = 2
LOG = 3
ERROR = 4


class Counter(object):
    __slots__ = ('value',)

    def __init__(self):
        self.value = 0

    def inc(self, value):
        self.value += value

    def __int__(self):
        return self.value

    def __str__(self):
        return str(self.value)


def _asunicode(x):
    if isinstance(x, str):
        try:
            return x.decode('utf-8')
        except UnicodeError:
            return x.decode('latin-1')
    elif isinstance(x, unicode):
        return x
    else:
        return unicode(x)


@config(category='admin')
class ODBC(PupyModule):
    ''' Query SQL using ODBC '''

    dependencies = ['pyodbc']

    terminate = None

    @classmethod
    def init_argparse(cls):

        cls.arg_parser = PupyArgumentParser(
            prog='odbc', description=cls.__doc__)

        commands = cls.arg_parser.add_subparsers(title='commands')

        register = commands.add_parser('register', help='Register driver')
        register.add_argument('name', help='Driver name (f.e. pg)')
        register.add_argument(
            '-d', '--description', help='Driver description')
        register.add_argument(
            'library', help='Driver library (f.e. psqlodbcw.so)')
        register.set_defaults(func=cls.register)

        drivers = commands.add_parser(
            'drivers', help='Show registered drivers')
        drivers.set_defaults(func=cls.drivers)

        bind = commands.add_parser('bind', help='Bind to server')
        bind.add_argument(
            '-a', '--alias',
            default='default', help='Short alias to identify connection'
        )
        bind.add_argument(
            '-e', '--encoding', help='Specify encoding'
        )
        bind.add_argument(
            'connstring', nargs=REMAINDER,
            help='ODBC connection string (read docs, pyodbc)')
        bind.set_defaults(func=cls.bind)

        unbind = commands.add_parser('unbind', help='Close connection by alias')
        unbind.add_argument('alias', nargs='?',
            help='Short alias to identify connection')
        unbind.set_defaults(func=cls.unbind)

        bounded = commands.add_parser('list', help='Show established connections')
        bounded.set_defaults(func=cls.bounded)

        tables = commands.add_parser('tables', help='Show tables')
        tables.add_argument(
            '-a', '--alias', default='default',
            help='Short alias to identify connection'
        )
        tables.add_argument(
            '-v', '--views', default=False, action='store_true',
            help='Show views and other types'
        )
        tables.add_argument(
            'filter', default=None, nargs=REMAINDER, help='Regex to filter names (ex: ^dbo)'
        )
        tables.set_defaults(func=cls.tables)

        describe = commands.add_parser('describe', help='Show table structure')
        describe.add_argument(
            '-a', '--alias', default='default',
            help='Short alias to identify connection'
        )
        describe.add_argument(
            'table', help='Table to describe'
        )
        describe.set_defaults(func=cls.describe)

        count = commands.add_parser(
            'count', help='Quick query, SELECT count(*) FROM <YOUR QUERY HERE>')
        count.add_argument(
            '-a', '--alias', default='default',
            help='Short alias to identify connection'
        )
        count.add_argument('query', nargs=REMAINDER, help='Part of count() query')
        count.set_defaults(func=cls.count)

        query = commands.add_parser('q', help='Query SQL statement')
        query.add_argument(
            '-a', '--alias', default='default',
            help='Short alias to identify connection'
        )
        query.add_argument(
            '-v', '--verbose', action='store_true', default=False,
            help='Show query, fetched records etc'
        )
        query.add_argument(
            '-l', '--limit', default=10, type=int,
            help='Send cancelation after this amount of records fetched'
        )

        output = query.add_mutually_exclusive_group()
        output.add_argument(
            '-D', '--dump', action='store_true', default=False,
            help='Save result to file (paths.odbc/md5(query).txt)'
        )
        output.add_argument(
            '-t', '--table', default=False, action='store_true',
            help='Try to draw table'
        )
        output.add_argument(
            '-T', '--tabs', default=False, action='store_true',
            help='Output with plain strings separated by tabs'
        )

        query.add_argument(
            'query', nargs=REMAINDER,
            help='SQL query (SELECT name FROM master.dbo.sysdatabases)')
        query.set_defaults(func=cls.query)

    def run(self, args):
        need_impl = self.client.remote('odbc', 'need_impl')
        if not self.client.is_windows() and need_impl():
            self.client.load_dll('libodbc.so')
            self.client.load_dll('libodbcinst.so')
            self.client.load_package('pyodbc')

        try:
            args.func(self, args)
        except Exception as e:
            if len(e.args) == 2 and e.args[1].startswith('['):
                self.error(
                    e.args[1].rsplit('\n', 1)[0].strip()
                )
            else:
                self.error(e)

    def bind(self, args):
        bind = self.client.remote('odbc', 'bind')
        connstring = ' '.join(args.connstring)
        alias = bind(args.alias, connstring, args.encoding)

        self.success('Bind: {} -> {}'.format(alias, connstring))

    def drivers(self, args):
        drivers = self.client.remote('odbc', 'drivers')
        self.log(List(drivers()))

    def register(self, args):
        register = self.client.remote('odbc', 'register_driver')
        drivers = self.client.remote('odbc', 'drivers')

        if register(args.name, args.description, args.library):
            self.client.load_dll(args.library)

        self.log(List(drivers()))

    def unbind(self, args):
        unbind = self.client.remote('odbc', 'unbind')
        alias = unbind(args.alias)

        self.success('Unbind: {}'.format(alias))

    def bounded(self, args):
        bounded = self.client.remote('odbc', 'bounded')
        aliased = bounded()
        if not aliased:
            return

        self.log(
            Table([
                {
                    'ALIAS': alias,
                    'CONNSTR': connstr
                } for (alias, connstr) in aliased
            ], ['ALIAS', 'CONNSTR'])
        )

    def describe(self, args):
        describe = self.client.remote('odbc', 'describe')
        description = describe(args.alias, args.table)
        self.log(
            Table([
                {
                    'COLUMN': col,
                    'TYPE': coltype
                } for (col, coltype) in description
            ], ['COLUMN', 'TYPE'])
        )

    def tables(self, args):
        tables = self.client.remote('odbc', 'tables')
        catalogs = tables(args.alias)
        if not catalogs:
            return

        re_filter = None

        if args.filter:
            re_filter = re_compile(' '.join(args.filter), IGNORECASE)

        for catalog, records in catalogs.iteritems():
            if args.views:
                self.log(
                    Table([
                        {
                            'TABLE': table, 'TYPE': tabletype
                        } for (table, tabletype) in records
                        if not re_filter or re_filter.match(table)
                    ], ['TABLE', 'TYPE'], caption=catalog)
                )
            else:
                self.log(
                    List([
                        table for (table, tabletype) in records
                        if not re_filter or re_filter.match(
                            table) and tabletype == 'TABLE'
                    ], caption=catalog)
                )

    def count(self, args):
        one = self.client.remote('odbc', 'one')
        if not args.query:
            self.error('Query is not specified')
            return

        query = 'SELECT count(*) FROM ' + ' '.join(args.query)

        self.info('QUERY: {}'.format(query))

        result = one(args.alias, query)

        if result:
            self.success('Count: {}'.format(result))

    def query(self, args):
        if not args.query:
            self.error('Query is not specified')
            return

        query = ' '.join(args.query)

        many = self.client.remote('odbc', 'many', False)

        completion = Event()
        header = []

        output = None

        total = Counter()

        if args.dump:
            config = self.client.pupsrv.config or PupyConfig()
            now = str(datetime.now())
            digest = md5(now + query).hexdigest()
            output = config.get_file('odbc', {
                '%c': self.client.short_name(),
                '%d': digest
            })

            index = join(
                dirname(output), 'index.txt'
            )

            self.info('Dumping to {}'.format(output))
            output = open(output, 'w+', encoding='utf-8')

            with open(index, 'a+') as indexobj:
                indexobj.write(u'{}\t{}\t{}\n'.format(digest, now, query))

        def on_data(code, payload):
            if code == END:
                completion.set()
                if args.verbose:
                    self.info('DONE [Total: {}]'.format(total))
            elif code == HEADER:
                del header[:]
                header.extend(payload)
                if output or args.tabs:
                    tabbed = u'\t'.join(_asunicode(col[0]) for col in header)
                    if output:
                        output.write(tabbed + '\n')
                    else:
                        self.log(tabbed)
            elif code == LOG:
                if args.verbose:
                    self.info(payload)
            elif code == ERROR:
                self.error(payload)
                completion.set()
            elif code != DATA:
                self.error('Unexpected code {}'.format(code))
            elif payload is None:
                return
            elif output or args.tabs:
                total.inc(len(payload))
                for record in payload:
                    tabbed = '\t'.join(_asunicode(col) for col in record)
                    if output:
                        output.write(tabbed + '\n')
                    else:
                        self.log(tabbed)
            elif args.table:
                titles = tuple(col[0] for col in header)
                total.inc(len(payload))

                self.log(
                    Table([
                        {
                            title: value
                            for title, value in zip(
                                titles, values
                            )
                        } for values in payload
                    ], titles)
                )
            else:
                total.inc(len(payload))
                titles = tuple(col[0] for col in header)

                if len(header) == 1:
                    for record in payload:
                        self.log(record[0])
                else:
                    for record in payload:
                        self.log(
                            List([
                                u'{}: {}'.format(title, value) for
                                (title, value) in zip(
                                    titles, record
                                )
                            ])
                        )
                        self.log(NewLine())

        if args.verbose:
            self.info('QUERY: {} LIMIT: {}'.format(query, args.limit))

        self.terminate = many(
            args.alias, query, args.limit, on_data
        )

        completion.wait()

    def interrupt(self):
        if self.terminate:
            self.terminate()
        else:
            raise NotImplementedError()
