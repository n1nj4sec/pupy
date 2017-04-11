# -*- coding: utf-8 -*-
import os
from pupylib.PupyModule import *
from pupylib.utils.rpyc_utils import obtain

__class_name__="MemStrings"

@config(cat="memstrings", compat=["windows", "linux"])
class MemStrings(PupyModule):
    """
        Dump printable strings from process memory for futher analysis
    """
    dependencies=['memorpy', 'memstrings']

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog='memstrings', description=self.__doc__)
        action = self.arg_parser.add_mutually_exclusive_group(required=True)
        action.add_argument('-p', '--pid', nargs='*', type=int, default=[])
        action.add_argument('-n', '--name', nargs='*', default=[])
        self.arg_parser.add_argument(
            '-log',
            help='Save output to file. Omit output to stdout. You can use vars: '
            '%%h - host, %%m - mac, %%P - platform, %%u - user, %%a - ip address'
            '%%p - pid, %%n - name'
        )

    def run(self, args):
        targets = args.pid + args.name
        dump = self.client.conn.modules.memstrings.find_strings(targets)
        dump = obtain(dump)
        if not dump:
            self.error('No dumps received')
            return

        self.success('Get {} dumps'.format(len(dump)))

        log = None

        for pid, items in dump.iteritems():
            name = items.get('name')
            strings = items.get('strings')

            if args.log:
                log = args.log.replace(
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
                    '%p', pid,
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

                self.success('Dump {}:{} to {}'.format(name, pid, log))
                with open(log, 'w') as log:
                    for s in strings:
                        log.write(s+'\n')

            else:
                self.success('Strings {}:{}'.format(name, pid))
                for s in strings:
                    self.stdout.write(s+'\n')

                self.stdout.write('\n')
