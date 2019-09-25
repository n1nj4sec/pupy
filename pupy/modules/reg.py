# -*- coding: utf-8 -*-

__class_name__ = 'reg'

from threading import Event

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.PupyOutput import (
    Color, List, Table, Line, MultiPart, TruncateToTerm
)

TYPES = (
    'NONE', 'SZ', 'EXPAND_SZ', 'BINARY', 'LE32', 'BE32',
    'LINK', 'MULTI_SZ', 'RESOURCE', 'RESOURCE_DESCRIPTOR',
    'RESOURCE_REQUIREMENTS_LIST', 'LE64'
)

TYPE_COLORS = {
    'NONE': 'darkgrey',
    'SZ': 'white',
    'EXPAND_SZ': 'cyan',
    'BINARY': 'grey',
    'LE32': 'lightgreen',
    'BE32': 'blue',
    'LE64': 'lightgreen',
    'LINK': 'lightyellow',
    'MULTI_SZ': 'lightred',
    'RESOURCE': 'red',
    'RESOURCE_DESCRIPTOR': 'red',
    'RESOURCE_REQUIREMENTS_LIST': 'red'
}

def as_unicode(x):
    if x is None:
        return None
    elif isinstance(x, unicode):
        return x
    elif isinstance(x, str):
        return x.decode('utf-8')
    else:
        return unicode(x)

def fix_key(x):
    x = as_unicode(x)
    x = x.strip()

    if x is None:
        return x
    elif '\\' not in x:
        x = x.replace('/', '\\')

    while '\\\\' in x:
        x = x.replace('\\\\', '\\')

    return x


@config(cat='admin', compatibilities=['windows'])
class reg(PupyModule):
    '''Search/list/get/set/delete registry keys/values '''

    __slots__ = ('interrupt_cb', '_last_key')

    dependencies = {
        'windows': ['reg']
    }

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog='reg', description=cls.__doc__)
        commands = cls.arg_parser.add_subparsers(dest='command')

        ls = commands.add_parser('ls')
        ls.add_argument('key', nargs='?', help='List key (HKCU by default)')
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

    def __init__(self, *args, **kwargs):
        super(reg, self).__init__(*args, **kwargs)
        self.interrupt_cb = None

    def run(self, args):
        self.interrupt_cb = None
        self._last_key = None

        try:
            if getattr(args, 'key', None):
                args.key = fix_key(args.key)

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
            key = as_unicode(key)

            if remove and key.startswith(remove):
                key = key[len(remove)+1:]

            if is_key:
                keys.append(key)
                continue

            name, value, ktype = rest

            ktype = TYPES[ktype]
            color = TYPE_COLORS[ktype]

            name = as_unicode(name)

            if ktype == 'BINARY':
                value = 'hex:' + value.encode('hex')
            else:
                value = as_unicode(value)

            if not wide and isinstance(value, (str,unicode)):
                value = value.strip()

            values.append({
                'KEY': Color(key, color),
                'NAME': Color(name, color),
                'VALUE': Color(value, color),
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
        result = ls(args.key)

        if result is None:
            self.error('No such key')
            return

        try:
            self._format_multi(result, wide=args.wide, remove=args.key)
        except:
            import traceback
            traceback.print_exc()

    def get(self, args):
        get = self.client.remote('reg', 'get')

        value = get(args.key, as_unicode(args.name))
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
            if kset(args.key, as_unicode(args.name), value, args.create):
                self.success('OK')
            else:
                self.error('No such key')
        except Exception, e:
            print e
            raise

    def rm(self, args):
        rm = self.client.remote('reg', 'rm')

        if rm(args.key, as_unicode(args.name)):
            self.success('OK')
        else:
            self.error('No such key')

    def interrupt(self):
        if self.interrupt_cb is None:
            self.warning('Interrupt is not supported')
            return

        self.interrupt_cb()

    def _format_by_one(self, record):
        is_key, key, rest = record[0], record[1], record[2:]

        if is_key is None:
            self.error(key)
            return

        if self._last_key != key:
            self._last_key = key
            self.log(Line('KEY:', Color(key, 'yellow')))

        if is_key:
            return

        name, value, ktype = rest

        ktype = TYPES[ktype]
        color = TYPE_COLORS[ktype]

        if type(value) in (str,unicode):
            value = value.strip()

        self.log(
            List([
                Line('Value:', Color(
                    value if ktype != 'BINARY' else repr(value), color)),
                Line('Type:', Color(ktype, color)),
            ], caption=Color(' > ' + name, color) if name else None)
        )

    def search(self, args):
        search = self.client.remote('reg', 'search', False)

        completed = Event()

        self.interrupt_cb = search(
            self._format_by_one, completed.set,
            as_unicode(args.term),
            tuple(fix_key(x) for x in args.roots.split(',')),
            args.exclude_key_name, args.exclude_value_name,
            args.exclude_value,
            args.regex, args.ignorecase,
            args.first, args.equals
        )

        self.info('Searching...')
        completed.wait()
        self.info('Done')
