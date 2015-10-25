# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

class Circuit(object):
	""" alias for obfsproxy style syntax"""
	def __init__(self, stream, transport):
		self.downstream=stream.downstream
		self.upstream=stream.upstream
		self.stream=stream
		self.transport=transport
	def close(self):
		self.transport.on_close()
		self.stream.close()

class BasePupyTransport(object):
	def __init__(self, stream):
		self.downstream=stream.downstream
		self.upstream=stream.upstream
		self.stream=stream
		self.circuit=Circuit(self.stream, self)

	def on_connect(self):
		"""
			We just established a connection. Handshake time ! :-)
		"""
		if hasattr(self, 'circuitConnected'):
			""" obfsproxy style alias """
			return self.circuitConnected()

	def on_close(self):
		"""
			called when the connection has been closed
		"""
		if hasattr(self, 'circuitDestroyed'):
			""" obfsproxy style alias """
			return self.circuitDestroyed()

	def downstream_recv(self, data):
		"""
			receiving obfuscated data from the remote client and writing deobfuscated data to downstream
		"""
		if hasattr(self, 'receivedDownstream'):
			""" obfsproxy style alias """
			return self.receivedDownstream(data)
		raise NotImplementedError()

	def upstream_recv(self, data):
		"""
			receiving clear-text data from local rpyc Stream and writing obfuscated data to upstream
		"""
		if hasattr(self, 'receivedUpstream'):
			return self.receivedUpstream(data)
			""" obfsproxy style alias """
		raise NotImplementedError()

class BaseTransport(BasePupyTransport):
	""" obfsproxy style alias """
	pass
class PluggableTransportError(Exception):
	pass
