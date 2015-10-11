# -*- coding: UTF8 -*-
# --------------------------------------------------------------
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
# 
# 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE
# --------------------------------------------------------------

from pupylib.PupyModule import *
import StringIO
import SocketServer
import threading
import socket
import logging
import struct
import traceback
import time

__class_name__="PortFwdModule"


class SocketPiper(threading.Thread):
	def __init__(self, read_sock, write_sock):
		threading.Thread.__init__(self)
		self.daemon=True
		self.read_sock=read_sock
		self.write_sock=write_sock
	def run(self):
		try:
			self.read_sock.setblocking(0)
			while True:
				data=""
				try:
					data+=self.read_sock.recv(1000000)
					if not data:
						break
				except Exception as e:
					if e[0]==9:#errno connection closed
						break
					if not data:
						time.sleep(0.05)
					continue
				self.write_sock.sendall(data)
		except Exception as e:
			logging.debug("error in socket piper: %s"%str(traceback.format_exc()))
		finally:
			try:
				self.write_sock.shutdown(socket.SHUT_RDWR)
				self.write_sock.close()
			except Exception:
				pass
			try:
				self.read_sock.shutdown(socket.SHUT_RDWR)
				self.read_sock.close()
			except Exception:
				pass
		logging.debug("piper finished")

class LocalPortFwdRequestHandler(SocketServer.BaseRequestHandler):
	def handle(self):
		DST_ADDR, DST_PORT=self.server.remote_address
		logging.debug("forwarding local addr %s to remote %s "%(self.server.server_address, self.server.remote_address))
		rsocket_mod=self.server.rpyc_client.conn.modules.socket
		rsocket=rsocket_mod.socket(rsocket_mod.AF_INET, rsocket_mod.SOCK_STREAM)
		rsocket.settimeout(5)
		try:
			rsocket.connect((DST_ADDR, DST_PORT))
		except Exception as e:
			logging.debug("error: %s"%e)
			if e[0]==10060:
				logging.debug("unreachable !")
			self.request.shutdown(socket.SHUT_RDWR)
			self.request.close()
			return
		logging.debug("connection succeeded !")
		sp1=SocketPiper(self.request, rsocket)
		sp2=SocketPiper(rsocket, self.request)
		sp1.start()
		sp2.start()
		sp1.join()
		sp2.join()
		logging.debug("conn to %s:%s closed"%(DST_ADDR,DST_PORT))

class LocalPortFwdServer(SocketServer.TCPServer):
	allow_reuse_address = True
	def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True, rpyc_client=None, remote_address=None):
		self.rpyc_client=rpyc_client
		self.remote_address=remote_address
		SocketServer.TCPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)

class ThreadedLocalPortFwdServer(SocketServer.ThreadingMixIn, LocalPortFwdServer):
	def __str__(self):
		return "<LocalPortForward local=%s remote=%s"%(self.server_address,self.remote_address)

class PortFwdModule(PupyModule):
	""" perform local/remote port forwarding using openssh -L/-R syntax """
	max_clients=1
	unique_instance=True
	daemon=True
	def __init__(self, *args, **kwargs):
		PupyModule.__init__(self, *args, **kwargs)
		self.portfwd_dic={}
		self.current_id=1

	def init_argparse(self):
		self.arg_parser = PupyArgumentParser(prog='socks5proxy', description=self.__doc__)
		self.arg_parser.add_argument('-L', '--local', help="Local port forward")
		self.arg_parser.add_argument('-R', '--remote', help="Remote port forward")
		self.arg_parser.add_argument('-k', '--kill', type=int, metavar="<id>", help="stop a port forward")

	def stop_daemon(self):
		#TODO
		pass

	def run(self, args):
		if args.local:
			tab=args.local.split(':')
			local_addr="127.0.0.1"
			local_port=None
			remote_addr=None
			remote_port=None

			if len(tab)==3:
				local_port, remote_addr, remote_port = tab
			elif len(tab)==4:
				local_addr, local_port, remote_addr, remote_port = tab
			else:
				self.error("usage: -L [<LOCAL_ADDR>]:<LOCAL_PORT>:<REMOTE_ADDR>:<REMOTE_PORT>")
				return
			try:
				local_port=int(local_port)
				remote_port=int(remote_port)
			except Exception:
				self.error("ports must be integers")
				return
			server = ThreadedLocalPortFwdServer((local_addr, local_port), LocalPortFwdRequestHandler, rpyc_client=self.client, remote_address=(remote_addr, remote_port))
			self.portfwd_dic[self.current_id]=server
			self.current_id+=1
			t=threading.Thread(target=server.serve_forever)
			t.daemon=True
			t.start()
			self.success("LOCAL %s:%s forwarded to REMOTE %s:%s"%(local_addr, local_port, remote_addr, remote_port))
		elif args.remote:
			#TODO remote port fwd
			raise NotImplementedError("remote port forwarding is not implemented yet")
		elif args.kill:
			if args.kill in self.portfwd_dic:
				desc=str(self.portfwd_dic[args.kill])
				self.portfwd_dic[args.kill].shutdown()
				del self.portfwd_dic[args.kill]
				self.success("%s stopped !"%desc)
			else:
				self.error("no such id: %s"%args.kill)
				
		else:
			if not self.portfwd_dic:
				self.error("There are currently no ports forwarded on %s"%self.client)
			else:
				for cid, server in self.portfwd_dic.iteritems():
					self.success("%s : %s"%(cid, server))


