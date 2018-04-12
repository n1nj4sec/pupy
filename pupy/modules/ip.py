# -*- coding: utf-8 -*-
from pupylib.PupyModule import *
from pupylib.PupyCmd import PupyCmd
from pupylib.PupyOutput import Color

import logging
import socket

__class_name__="IPModule"

@config(cat="admin")
class IPModule(PupyModule):
    """ list interfaces """

    dependencies = [ 'pupyps' ]
    is_module=False

    io = REQUIRE_STREAM

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="ip", description=cls.__doc__)
        cls.arg_parser.add_argument('iface', nargs='*', help='show only these interfaces')

    def run(self, args):
        try:
            pupyps = self.client.remote('pupyps')
            interfaces = self.client.remote('pupyps', 'interfaces')
            families = {
                int(k):v for k,v in self.client.remote_const(
                    'pupyps', 'families'
                ).iteritems()
            }

            data = interfaces()
            families = { int(x):y for x,y in families.iteritems() }

            addrlen = max([len(x) for x in data['addrs']])+1

            familylen = max([len(v)-3 for v in families.itervalues()])+1

            for addr, addresses in data['addrs'].iteritems():
                if args.iface and not addr in args.iface:
                    continue

                color = ""
                if 'stats' in data and data['stats']:
                    if addr in data['stats'] and not data['stats'][addr].get('isup'):
                        color = 'darkgrey'
                    elif not any([ families[x.get('family')] == 'INET' for x in addresses ]):
                        color = 'grey'
                else:
                    color = 'white'

                self.stdout.write(Color(addr.ljust(addrlen), color or 'cyan'))
                first = True

                for address in addresses:
                    if first:
                        first = False
                    else:
                        self.stdout.write(' '*addrlen)

                    self.stdout.write(Color(families[
                        address.get('family')
                    ].ljust(familylen), color))

                    self.stdout.write(
                        Color(address.get('address', '').split('%')[0], color or 'yellow')
                    )

                    if address.get('netmask') != 'None':
                        self.stdout.write(Color('/'+address.get('netmask'), color))

                    if address.get('broadcast') != 'None':
                        self.stdout.write(Color(' brd '+address.get('broadcast'), color))
                    self.stdout.write('\n')

        except Exception, e:
            logging.exception(e)
