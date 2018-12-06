# -*- coding: utf-8 -*-

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.PupyOutput import Color

import logging

__class_name__="NetStatModule"

ADMINS = (r'NT AUTHORITY\SYSTEM', 'root')

def to_unicode(x):
    if type(x) == str:
        return x.decode('utf-8')
    elif type(x) == unicode:
        return x
    else:
        return unicode(x)

@config(cat="admin")
class NetStatModule(PupyModule):
    """ list terminal sessions """

    dependencies = ['pupyps']
    is_module=False

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="netstat", description=cls.__doc__)
        cls.arg_parser.add_argument('-l', '--listen', action='store_true', help='Show listening sockets')
        cls.arg_parser.add_argument('-t', '--tcp', action='store_true', help='Show TCP')
        cls.arg_parser.add_argument('-u', '--udp', action='store_true', help='Show UDP')
        cls.arg_parser.add_argument('-s', '--show', nargs='+', default=[], help='Filter by word')
        cls.arg_parser.add_argument('-x', '--hide', nargs='+', default=[], help='Filter out by word')

    def run(self, args):
        try:
            connections = self.client.remote('pupyps', 'connections')

            families = {
                int(k):v for k,v in self.client.remote_const(
                    'pupyps', 'families'
                ).iteritems()
            }

            socktypes = {
                int(k):v for k,v in self.client.remote_const(
                    'pupyps', 'socktypes'
                ).iteritems()
            }

            data = connections()

            limit = []

            if args.tcp:
                limit.append('STREAM')
            if args.udp:
                limit.append('DGRAM')

            objects = []
            for connection in data:
                if connection['status'] == 'LISTEN' and not args.listen:
                    continue

                if args.listen and not connection['status'] == 'LISTEN':
                    continue

                color = ""
                family = families[connection['family']]
                stype = socktypes[connection['type']]

                if limit and stype not in limit:
                    continue

                if connection.get('me'):
                    color = 'green'
                elif connection['status'] in ('CLOSE_WAIT', 'TIME_WAIT', 'TIME_WAIT2'):
                    color = 'darkgrey'
                elif ('127.0.0.1' in connection['laddr'] or '::1' in connection['laddr']):
                    color = 'grey'

                deny = False
                if args.show or '*' in args.hide:
                    deny = True

                connection = {
                    'AF': Color(family, color),
                    'TYPE': Color(stype, color),
                    'LADDR': Color(':'.join([str(x) for x in connection['laddr']]), color),
                    'RADDR': Color(':'.join([str(x) for x in connection['raddr']]), color),
                    'PID': Color(connection.get('pid', ''), color),
                    'USER': Color((connection.get('username') or ''), color),
                    'EXE': Color(
                        connection.get(
                            'exe', (connection.get('name') or '')
                        ), color)
                }

                for v in connection.itervalues():
                    if any(to_unicode(h) in to_unicode(v.data) for h in args.hide):
                        deny = True
                    if any(to_unicode(h) in to_unicode(v.data) for h in args.show):
                        deny = False

                if not deny:
                    objects.append(connection)

            self.table(objects, [
                'AF', 'TYPE', 'LADDR', 'RADDR', 'USER', 'PID', 'EXE'
            ], truncate=True)

        except Exception, e:
            logging.exception(e)
