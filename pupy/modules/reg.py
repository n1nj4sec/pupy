# -*- coding: utf-8 -*-

__class_name__ = 'reg'

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.PupyOutput import Color, List, Table, MultiPart, TruncateToTerm

TYPES = (
    'NONE', 'SZ', 'EXPAND_SZ', 'BINARY', 'LE32', 'BE32',
    'LINK', 'MULTI_SZ', 'RESOURCE', 'RESOURCE_DESCRIPTOR',
    'RESOURCE_REQUIREMENTS_LIST'
)

TYPE_COLORS = {
    'NONE': 'darkgrey',
    'SZ': 'white',
    'EXPAND_SZ': 'cyan',
    'BINARY': 'grey',
    'LE32': 'lightgreen',
    'BE32': 'blue',
    'LINK': 'lightyellow',
    'MULTI_SZ': 'lightred',
    'RESOURCE': 'red',
    'RESOURCE_DESCRIPTOR': 'red',
    'RESOURCE_REQUIREMENTS_LIST': 'red'
}

def as_unicode(x):
    if type(x) is str:
        return x.decode('utf-8')
    elif type(x) is unicode:
        return x
    else:
        return unicode(x)

@config(cat='admin', compatibilities=['windows'])
class reg(PupyModule):
    '''Search/list/get/set/delete registry keys/values '''

    dependencies = {
        'windows': ['reg']
    }

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog='reg', description=cls.__doc__)
        commands = cls.arg_parser.add_subparsers(dest='command')

        ls = commands.add_parser('ls')
        ls.add_argument('key', default='HKCU', help='List key (HKCU by default)')
        ls.add_argument('-w', '--wide', action='store_true', default=False, help='Show all the things')
        ls.set_defaults(func=cls.ls)

        get = commands.add_parser('get')
        get.add_argument('key', help='Key path (no default)')
        get.add_argument(
            'name', nargs='?', default='',
            help='Value name (default is Default value)')
        get.set_defaults(func=cls.get)

        vset = commands.add_parser('set')
        vset.add_argument(
            '-c', '--create', action='store_true', default=False,
            help='Create key')
        vset.add_argument(
            '-i', '--integer', action='store_true', default=False,
            help='Set as DWORD/LE32, default SZ (string)')
        vset.add_argument('key', help='Key path')
        vset.add_argument('name', help='Value name to set')
        vset.add_argument('value', help='Value to set')
        vset.set_defaults(func=cls.set)

        rm = commands.add_parser('rm')
        rm.add_argument('key', help='Key path')
        rm.add_argument('name', default='', nargs='?', help='Value name or subkey to delete')
        rm.set_defaults(func=cls.rm)

        search = commands.add_parser('search')
        search.add_argument(
            '-r', '--roots', default='HKU,HKLM,HKCC', help='Roots where to search ("," is delemiter)')
        search.add_argument(
            '-K', '--exclude-key-name', action='store_false', default=True,
            help='Do not search term in key names')
        search.add_argument(
            '-N', '--exclude-value-name', action='store_false', default=True,
            help='Do not search term in value names')
        search.add_argument(
            '-V', '--exclude-value', action='store_false', default=True,
            help='Do not search term in values')
        search.add_argument(
            '-R', '--regex', action='store_true', default=False,
            help='Search term is regex')
        search.add_argument(
            '-E', '--equals', action='store_true', default=False,
            help='Show only full matches')
        search.add_argument(
            '-i', '--ignorecase', action='store_true', default=False,
            help='Ignore case')
        search.add_argument(
            '-w', '--wide', action='store_true', default=False,
            help='Show all the things')
        search.add_argument(
            '-1', '--first', action='store_true', default=False,
            help='Return after first match')
        search.add_argument('term', help='Term to search')
        search.set_defaults(func=cls.search)

    def run(self, args):
        try:
            args.func(self, args)

        except Exception, e:
            if e.args[0] == 5:
                self.error('Access denied')
            elif e.args[0] == 'ascii':
                self.error('Encoding error: {}'.format(e))
            else:
                self.error('Error: {}'.format(e.args[0]))

    def _format_multi(self, results, wide=False, remove=None):
        keys = []
        values = []

        legend = ['NAME', 'TYPE', 'VALUE']
        if not remove:
            legend.insert(0, 'KEY')

        for record in results:
            is_key, key, rest = record[0], record[1], record[2:]

            if remove and key.startswith(remove):
                key = key[len(remove)+1:]

            if is_key:
                keys.append(key)
                continue

            name, value, ktype = rest

            ktype = TYPES[ktype]
            color = TYPE_COLORS[ktype]

            if not wide and type(value) in (str,unicode):
                value = value.strip()

            values.append({
                'KEY': Color(key, color),
                'NAME': Color(name, color),
                'VALUE': Color(value if ktype != 'BINARY' else repr(value), color),
                'TYPE': Color(ktype, color)
            })

        results = []

        if keys:
            results.append(List(keys, caption='{ Keys }'))

        if values:
            results.append(Table(values, legend, caption='Values'))

        if not keys and not values:
            self.log('Empty')
        else:
            results = MultiPart(results)
            if not wide:
                results = TruncateToTerm(results)
            self.log(results)

    def ls(self, args):
        ls = self.client.remote('reg', 'enum')
        result = ls(as_unicode(args.key))

        if result is None:
            self.error('No such key')
            return

        self._format_multi(result, wide=args.wide, remove=args.key)

    def get(self, args):
        get = self.client.remote('reg', 'get')

        value = get(as_unicode(args.key), as_unicode(args.name))
        if value is None:
            self.error('No such key')
        else:
            self.log(value)

    def set(self, args):
        kset = self.client.remote('reg', 'set')
        value = args.value

        if args.integer:
            value = int(value)
        else:
            value = as_unicode(value)

        try:
            if kset(as_unicode(args.key), as_unicode(args.name), value, args.create):
                self.success('OK')
            else:
                self.error('No such key')
        except Exception, e:
            print e
            raise

    def rm(self, args):
        rm = self.client.remote('reg', 'rm')

        if rm(as_unicode(args.key), as_unicode(args.name)):
            self.success('OK')
        else:
            self.error('No such key')

    def search(self, args):
        search = self.client.remote('reg', 'search')
        results = search(
            as_unicode(args.term),
            tuple([as_unicode(x.strip()) for x in args.roots.split(',')]),
            args.exclude_key_name, args.exclude_value_name,
            args.exclude_value,
            args.regex, args.ignorecase,
            args.first, args.equals
        )

        self._format_multi(results, wide=args.wide)
