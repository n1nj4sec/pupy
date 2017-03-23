# -*- coding: utf-8 -*-
from pupylib.PupyModule import *
from pupylib.PupyCmd import PupyCmd
from pupylib.utils.rpyc_utils import obtain
from pupylib.utils.term import colorize
from modules.lib.utils.shell_exec import shell_exec
from collections import OrderedDict
from datetime import datetime, timedelta

import logging
import socket

__class_name__="NetStatModule"

ADMINS = ('NT AUTHORITY\SYSTEM', 'root')

@config(cat="admin")
class NetStatModule(PupyModule):
    """ list terminal sessions """

    dependencies = [ 'pupyps' ]
    is_module=False

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="netstat", description=self.__doc__)
        self.arg_parser.add_argument('-l', '--listen', action='store_true', help='Show listening sockets')
        self.arg_parser.add_argument('-t', '--tcp', action='store_true', help='Show TCP')
        self.arg_parser.add_argument('-u', '--udp', action='store_true', help='Show UDP')

    def run(self, args):
        try:
            rpupyps = self.client.conn.modules.pupyps
            data = obtain(rpupyps.connections())
            sock = { int(x):y for x,y in obtain(rpupyps.socktypes).iteritems() }
            families = { int(x):y for x,y in obtain(rpupyps.families).iteritems() }

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
                stype = sock[connection['type']]

                if limit and not stype in limit:
                    continue

                if connection.get('me'):
                    color = 'green'
                elif connection['status'] in ('CLOSE_WAIT', 'TIME_WAIT', 'TIME_WAIT2'):
                    color = 'darkgrey'
                elif ( '127.0.0.1' in connection['laddr'] or '::1' in connection['laddr'] ):
                    color = 'grey'

                objects.append({
                    'AF': colorize(family, color),
                    'TYPE': colorize(stype, color),
                    'LADDR': colorize(':'.join([str(x) for x in connection['laddr']]), color),
                    'RADDR': colorize(':'.join([str(x) for x in connection['raddr']]), color),
                    'PID': colorize(connection.get('pid', ''), color),
                    'USER': colorize(connection.get('username', '').encode('utf8','replace'), color),
                    'EXE': colorize(
                        connection.get(
                            'exe', connection.get('name', '').encode('utf8','replace')
                        ), color)
                })

            self.stdout.write(
                PupyCmd.table_format(objects, wl=[
                    'AF', 'TYPE', 'LADDR', 'RADDR', 'USER', 'PID', 'EXE'
                ]))

        except Exception, e:
            logging.exception(e)
