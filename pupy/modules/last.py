# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.PupyOutput import Color
from datetime import datetime, timedelta

import logging

__class_name__="LastModule"

@config(cat='admin', compat=['linux', 'windows'])
class LastModule(PupyModule):
    """ list terminal sessions """

    dependencies = {
        'linux': ['pupyps'],
        'windows': ['readlogs', 'pupwinutils.security']
    }

    is_module=False

    @classmethod
    def init_argparse(cls):
        arg_parser = PupyArgumentParser(prog="last", description=cls.__doc__)
        duration = arg_parser.add_mutually_exclusive_group()
        duration.add_argument('-n', '--lines', type=int, help='Get only (n) last records')
        duration.add_argument('-d', '--days', type=int, help='Get only records for last (n) days')
        filtering = arg_parser.add_mutually_exclusive_group()
        filtering.add_argument('-x', '--exclude', nargs='+', help='Hide users/hosts/ips')
        filtering.add_argument('-i', '--include', nargs='+', help='Show users/hosts/ips')
        cls.arg_parser = arg_parser

    def run(self, args):
        try:
            wtmp = None

            is_windows = False

            if self.client.is_windows():
                wtmp = self.client.remote('readlogs', 'lastlog')
                is_windows = True
            else:
                wtmp = self.client.remote('pupyps', 'wtmp')

            data = wtmp()

            now = data['now']
            output = []

            for record in data['records']:
                if args.days and (record['start'] + args.days*24*60*60 < now):
                    break

                if args.exclude and any([x in args.exclude for x in record.itervalues()]):
                    continue

                if args.include and not any([x in args.include for x in record.itervalues()]):
                    continue

                if not is_windows and record['type'] not in ('boot', 'process'):
                    continue

                color = ''
                if record['end'] == -1:
                    if record['user'] == 'root':
                        color = 'lightred'
                    elif record['duration'] < 60*60:
                        color = 'lightgreen'
                    elif record['duration'] > 7*24*60*60:
                        color = 'cyan'
                elif record['user'] == 'root':
                    color = 'yellow'
                elif record['end'] > 24*60*60:
                    color = 'grey'
                elif record['end'] > 7*24*60*60:
                    color = 'darkgrey'

                if record['type'] == 'boot':
                    color = 'yellow'

                record['start'] = datetime.fromtimestamp(record['start'])
                record['end'] = datetime.fromtimestamp(
                    record['end']
                ) if record['end'] is not None and record['end'] != -1 else 'logged in'
                record['duration'] = timedelta(seconds=int(record['duration']))
                record['ip'] = '' if record['ip'] == '0.0.0.0' else record['ip']

                if record['type'] == 'boot' and record['end'] == 'logged in':
                    record['end'] = 'up'

                for f in record:
                    if record[f]:
                        record[f] = Color(str(record[f]), color)

                output.append(record)

                if args.lines and len(output) >= args.lines:
                    break

            columns = [
                x for x in [
                    'user', 'line', 'pid', 'host', 'ip', 'start', 'end', 'duration'
                ] if any((x in y and y[x]) for y in output)
            ]

            self.table(output, columns)

        except Exception as e:
            logging.exception(e)
