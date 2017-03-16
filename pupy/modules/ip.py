# -*- coding: utf-8 -*-
from pupylib.PupyModule import *
from pupylib.PupyCmd import PupyCmd
from pupylib.utils.rpyc_utils import obtain
from pupylib.utils.term import colorize
from datetime import datetime, timedelta

import logging
import socket

__class_name__="IPModule"

@config(cat="admin")
class IPModule(PupyModule):
    """ list interfaces """

    dependencies = [ 'pupyps' ]
    is_module=False

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="ip", description=self.__doc__)
        self.arg_parser.add_argument('iface', nargs='*', help='show only these interfaces')

    def run(self, args):
        try:
            data = obtain(self.client.conn.modules.pupyps.interfaces())

            addrlen = max([len(x) for x in data['addrs']])+1

            families = {
                v:k[3:] for k,v in socket.__dict__.iteritems() if k.startswith('AF_')
            }

            families.update({-1: 'LINK'})

            familylen = max([len(v)-3 for v in families.itervalues()])+1

            for addr, addresses in data['addrs'].iteritems():
                if args.iface and not addr in args.iface:
                    continue

                color = ""
                if addr in data['stats'] and not data['stats'][addr].get('isup'):
                    color = 'darkgrey'
                elif not any([ x.get('family') == socket.AF_INET for x in addresses ]):
                    color = 'grey'

                self.stdout.write(colorize(addr.ljust(addrlen), color or 'cyan'))
                first = True

                for address in addresses:
                    if first:
                        first = False
                    else:
                        self.stdout.write(' '*addrlen)

                    self.stdout.write(colorize(families[
                        address.get('family')
                    ].ljust(familylen), color))

                    self.stdout.write(
                        colorize(address.get('address', '').split('%')[0], color or 'yellow')
                    )
                    if address.get('netmask'):
                        self.stdout.write(colorize('/'+address.get('netmask'), color))

                    if address.get('broadcast'):
                        self.stdout.write(colorize(' brd '+address.get('broadcast'), color))
                    self.stdout.write('\n')

        except Exception, e:
            logging.exception(e)
