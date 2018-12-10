# -*- coding: utf-8 -*-

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.PupyOutput import TruncateToTerm, List, Color, Line

from datetime import datetime

__class_name__='Logs'
@config(cat='admin', compat=['posix', 'windows'])
class Logs(PupyModule):
    ''' Show logs (or try to search something) '''

    dependencies = {
        'posix': ['readlogs_generic'],
        'all': ['readlogs']
    }

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog='logs', description=cls.__doc__)
        cls.arg_parser.add_argument('-n', '--number', type=int, default=10,
                        help='Show last n records of each category (if applicable)')
        cls.arg_parser.add_argument('-i', '--include', action='append', default=[],
                        help='Add regex to include content')
        cls.arg_parser.add_argument('-x', '--exclude', action='append', default=[],
                        help='Add regex to exclude content')
        cls.arg_parser.add_argument('-t', '--time', action='store_true', default=False,
                        help='Show time')
        cls.arg_parser.add_argument('-w', '--width', action='store_true', default=False,
                        help='Show full content')


    def run(self, args):
        get_last_events = self.client.remote('readlogs', 'get_last_events')
        today = datetime.now().date()

        def make_fields(item):
            items = []
            if args.time:
                date = datetime.fromtimestamp(item['date'])
                date_str = ''
                if date.date() == today:
                    date_str = date.strftime('%H:%M:%S')
                elif date.date().year == today.year:
                    date_str = date.strftime('%d/%m %H:%M:%S')
                else:
                    date_str = date.strftime('%Y/%d/%m %H:%M:%S')

                items.append(Color(date_str, 'lightgrey'))

            if 'EventID' in item:
                items.append(Color('EventID: ' + str(item['EventID']), 'green'))

            msg = item['msg']

            if not args.width:
                msg = ' '.join([x.strip() for x in msg.split('\n')])

            if item.get('type') in ('CRITICAL', 'EMERGENCY', 'ALERT', 'ERROR'):
                msg = Color(msg, 'lightred')
            elif item.get('type') == 'WARNING':
                msg = Color(msg, 'lightyellow')
            elif item.get('type') == 'DEBUG':
                msg = Color(msg, 'grey')

            items.append(msg)
            return Line(*items)

        for category, events in get_last_events(args.number, args.include, args.exclude).iteritems():
            if not events:
                continue

            data = List([
                    make_fields(x) for x in events
                ], indent=0, bullet='+' if args.include or args.exclude else '', caption=Color(
                    '> ' + category, 'yellow'))

            if not args.width:
                data = TruncateToTerm(data)

            self.log(data)
