# -*- coding: utf-8 -*-
from pupylib.PupyModule import *

__class_name__="DNS"

@config(cat="admin")
class DNS(PupyModule):
    """ retrieve domain name from IP and vice versa """

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="dns", description=self.__doc__)
        self.arg_parser.add_argument('ip_or_domain', type=str, help='Domain name or IP address')

    def run(self, args):
        self.client.load_package("pupyutils.dns")
        functions = self.client.conn.modules["pupyutils.dns"].launch_dns_ip_resolver(args.ip_or_domain)
        for function in functions:
            if functions[function]['result']:
                self.success('%s: %s' % (function, functions[function]['result']))
            else:
                self.error('%s: Not found' % function)
