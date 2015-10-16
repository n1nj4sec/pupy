#!/usr/bin/env python
# -*- coding: UTF8 -*-
""" abstraction layer over rpyc streams to handle different transports and integrate obfsproxy pluggable transports """
from rpyc.core import SocketStream
from .buffer import Buffer
import socket
import time
import errno
import logging
import traceback
from rpyc.lib.compat import select, select_error, BYTES_LITERAL, get_exc_errno, maxint

class PupySocketStream(SocketStream):
	def __init__(self, sock, transport_class):
		super(PupySocketStream, self).__init__(sock)
		#buffers for streams
		self.buf_in=Buffer()
		self.buf_out=Buffer()
		#buffers for transport
		self.upstream=Buffer()
		self.downstream=Buffer(on_write=self._upstream_recv)
		self.transport=transport_class(self)
		self.on_connect()

	def on_connect(self):
		self.transport.on_connect()
		super(PupySocketStream, self).write(self.downstream.read())

	def _read(self):
		try:
			#buf = self.sock.recv(min(self.MAX_IO_CHUNK, count))
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
		#print "upstream_recv"
		#print "downstream=%s"%len(self.downstream)
		#print "upstream=%s"%len(self.upstream)
		if len(self.downstream)>0:
			#print "writing %s"%len(self.downstream.peek())
			super(PupySocketStream, self).write(self.downstream.read())

	def read(self, count):
		try:
			if len(self.upstream)>=count:
				return self.upstream.read(count)
			while len(self.upstream)<count:
				if self.sock_poll(0):#to avoid waiting on the socket while a transport write on the upstream buffer resulting in deadlock
					self._read()
					self.transport.downstream_recv(self.buf_in)
				if len(self.upstream)<count:
					time.sleep(0.1)#to avoid active wait
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

