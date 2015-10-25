#!/usr/bin/env python
# -*- coding: UTF8 -*-
from rpyc.utils.server import ThreadPoolServer
from rpyc.core import Channel, Connection
from rpyc.utils.authenticators import AuthenticationError

class PupyTCPServer(ThreadPoolServer):
	def __init__(self, *args, **kwargs):
		if not "stream" in kwargs:
			raise ValueError("missing stream_class argument")
		if not "transport" in kwargs:
			raise ValueError("missing transport argument")
		self.stream_class=kwargs["stream"]
		self.transport_class=kwargs["transport"]
		self.transport_kwargs=kwargs["transport_kwargs"]
		del kwargs["stream"]
		del kwargs["transport"]
		del kwargs["transport_kwargs"]

		ThreadPoolServer.__init__(self, *args, **kwargs)

	def _authenticate_and_build_connection(self, sock):
		'''Authenticate a client and if it succeeds, wraps the socket in a connection object.
		Note that this code is cut and paste from the rpyc internals and may have to be
		changed if rpyc evolves'''
		# authenticate
		if self.authenticator:
			h, p = sock.getpeername()
			try:
				sock, credentials = self.authenticator(sock)
			except AuthenticationError:
				self.logger.info("%s:%s failed to authenticate, rejecting connection", h, p)
				return None
		else:
			credentials = None
		# build a connection
		h, p = sock.getpeername()
		config = dict(self.protocol_config, credentials=credentials, connid="%s:%d"%(h, p))
		return Connection(self.service, Channel(self.stream_class(sock, self.transport_class, self.transport_kwargs)), config=config)

