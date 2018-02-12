# -*- coding: utf-8 -*-
from pupylib.PupyModule import *

__class_name__="DNS"

@config(cat="admin")
class DNS(PupyModule):
    """ retrieve domain name from IP and vice versa """

    dependencies = [ 'pupyutils.dns' ]

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="dns", description=self.__doc__)
        self.arg_parser.add_argument('ip_or_domain', type=str, help='Domain name or IP address')

    def run(self, args):
        launch_dns_ip_resolver = self.client.remote('pupyutils.dns', 'launch_dns_ip_resolver')
        for k,v in launch_dns_ip_resolver(args.ip_or_domain).iteritems():
            if v:
                self.success('{}: {}'.format(k, v if type(v) is str else ','.join(v)))
            else:
                self.error('{}: Not found'.format(k))
