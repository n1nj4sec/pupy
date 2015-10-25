# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
""" abstraction layer over rpyc streams to handle different transports and integrate obfsproxy pluggable transports """
import sys
from rpyc.core import SocketStream
from .buffer import Buffer
import socket
import time
import errno
import logging
import traceback
from rpyc.lib.compat import select, select_error, BYTES_LITERAL, get_exc_errno, maxint
import threading
retry_errnos = (errno.EAGAIN, errno.EWOULDBLOCK)

class addGetPeer(object):
	""" add some functions needed by some obfsproxy transports"""
	def __init__(self, peer):
		self.peer=peer
	def getPeer(self):
		return self.peer

class PupySocketStream(SocketStream):
	def __init__(self, sock, transport_class, transport_kwargs={}):
		super(PupySocketStream, self).__init__(sock)
		#buffers for streams
		self.buf_in=Buffer()
		self.buf_out=Buffer()
		#buffers for transport
		self.upstream=Buffer(transport_func=addGetPeer(("127.0.0.1", 443)))
		self.downstream=Buffer(on_write=self._upstream_recv, transport_func=addGetPeer(sock.getpeername()))

		self.transport=transport_class(self, **transport_kwargs)
		self.on_connect()
		#self.async_read_thread=threading.Thread(target=self._downstream_recv_loop)
		#self.async_read_thread.daemon=True
		#self.async_read_thread.start()

	def on_connect(self):
		self.transport.on_connect()
		super(PupySocketStream, self).write(self.downstream.read())

	def _read(self):
		try:
			buf = self.sock.recv(self.MAX_IO_CHUNK)
		except socket.timeout:
			return
		except socket.error:
			ex = sys.exc_info()[1]
			if get_exc_errno(ex) in retry_errnos:
				# windows just has to be a bitch
				return
			self.close()
			raise EOFError(ex)
		if not buf:
			self.close()
			raise EOFError("connection closed by peer")
		self.buf_in.write(BYTES_LITERAL(buf))

	def poll(self, timeout):
		return len(self.upstream)>0 or super(PupySocketStream, self).poll(timeout)

	def sock_poll(self, timeout):
		return super(PupySocketStream, self).poll(timeout)

	def _upstream_recv(self):
		""" called as a callback on the downstream.write """
		if len(self.downstream)>0:
			super(PupySocketStream, self).write(self.downstream.read())

	def _downstream_recv_loop(self):
		try:
			while True:
				self._read()
				self.transport.downstream_recv(self.buf_in)
		except EOFError as e:
			self.upstream.set_eof(e)


	def read(self, count):
		try:
			if len(self.upstream)>=count:
				return self.upstream.read(count)
			while len(self.upstream)<count:
				if self.sock_poll(0):
					self._read()
					self.transport.downstream_recv(self.buf_in)
				#it seems we can actively wait here with only perf enhancement
				#if len(self.upstream)<count:
				#	self.upstream.wait(0.1)#to avoid active wait
			return self.upstream.read(count)
		except Exception as e:
			logging.debug(traceback.format_exc())

	def write(self, data):
		try:
			self.buf_out.write(data)
			self.transport.upstream_recv(self.buf_out)
			#The write will be done by the _upstream_recv callback on the downstream buffer
		except Exception as e:
			logging.debug(traceback.format_exc())

