# -*- coding: utf-8 -*-

import threading

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.PupyOutput import Table

from netaddr import IPAddress
from netaddr.core import AddrFormatError

__class_name__="PortScan"

@config(cat="network")
class PortScan(PupyModule):
    """ run a TCP port scan """

    abort = None

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="port_scan", description=cls.__doc__)
        cls.arg_parser.add_argument('--ports','-p', default="21,22,23,80,139,443,445,1433,1521,3389,7001,8000,8080",  help='ports to scan ex: 22,80,443')
        cls.arg_parser.add_argument('--timeout', default=10, type=int,
                                    help='timeout (default: %(default)s)')
        cls.arg_parser.add_argument('--portion', default=32, type=int,
                                    help='number of ports scanned per timeout (default: %(default)s)')
        cls.arg_parser.add_argument('target', metavar="ip/range", help='IP/range')

    def run(self, args):
        self.terminated = threading.Event()

        scanthread = self.client.remote('network.lib.scan', 'scanthread_parse', False)

        connectable = []

        def set_connectable(addrs):
            connectable.extend(addrs)
            self.terminated.set()

        def on_exception(exception):
            self.error('Internal Error: {}'.format(exception))
            self.terminated.set()

        self.abort = scanthread(
            args.target, args.ports, set_connectable,
            on_exception=on_exception,
            timeout=args.timeout, portion=args.portion
        )

        self.terminated.wait()

        if connectable:
            objects = {}
            for host, port in connectable:
                try:
                    host = IPAddress(host)
                except AddrFormatError:
                    pass

                port = int(port)

                if host in connectable:
                    objects[host].add(port)
                else:
                    objects[host] = set([port])

            self.log(Table(
                list({
                    'IP': str(host),
                    'PORTS': ', '.join([str(port) for port in sorted(list(objects[host]))])
                } for host in sorted(objects.keys())),
                ['IP', 'PORTS']))
        else:
            self.error('No connectable ports found')

        self.abort = None

    def interrupt(self):
        if self.abort:
            self.abort.set()

        if self.terminated:
            self.terminated.set()
