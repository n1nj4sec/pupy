# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.PupyOutput import Color, Line, Table

from network.lib.compat import as_attr_type

import logging

__class_name__ = 'IPModule'


@config(cat="admin")
class IPModule(PupyModule):
    """ list interfaces """

    dependencies = ['pupyps']
    is_module=False

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(
            prog='ip', description=cls.__doc__
        )

        cls.arg_parser.add_argument(
            'iface', nargs='*', help='show only these interfaces'
        )

    def run(self, args):
        try:
            interfaces = self.client.remote('pupyps', 'interfaces')
            families = {
                int(k): as_attr_type(v) for k, v in self.client.remote_const(
                    'pupyps', 'families'
                ).items()
            }

            data = interfaces()
            families = {
                int(x): as_attr_type(y) for x, y in families.items()
            }

            objects = []

            for addr, addresses in data['addrs'].items():
                if args.iface and addr not in args.iface:
                    continue

                color = ''
                if 'stats' in data and data['stats']:
                    if addr in data['stats'] and not data['stats'][addr].get('isup'):
                        color = 'darkgrey'
                    elif not any([families[x.get('family')] == 'INET' for x in addresses]):
                        color = 'grey'
                else:
                    color = 'white'

                record = {}
                record['K'] = Color(addr, color or 'cyan')

                first = True

                for address in addresses:
                    if first:
                        first = False
                    else:
                        record = {}
                        record['K'] = ''

                    record['F'] = Color(families[address.get('family')], color)
                    V = Color(address.get('address', '').split('%')[0], color or 'yellow')

                    if address.get('netmask') != 'None':
                        V = Line(V, Color(address.get('netmask'), color))
                        V.dm = '/'

                    if address.get('broadcast') != 'None':
                        V = Line(V, Color('brd '+address.get('broadcast'), color))

                    record['V'] = Line(V)

                    objects.append(record)

            self.log(Table(objects, ['K', 'F', 'V'], legend=False))

        except Exception as e:
            logging.exception(e)
