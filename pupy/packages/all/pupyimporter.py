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
# This module uses the builtins modules pupy and _memimporter to load python modules and packages from memory, including .pyd files (windows only)
# Pupy can dynamically add new modules to the modules dictionary to allow remote importing of python modules from memory !
#
import sys, imp, zlib, marshal
builtin_memimporter=False
try:
	import _memimporter
	builtin_memimporter=True
except ImportError:
	pass
	
modules={}
try:
	import pupy
	if not (hasattr(pupy, 'pseudo') and pupy.pseudo):
		modules = marshal.loads(zlib.decompress(pupy._get_compressed_library_string()))
except ImportError:
	#modules = marshal.loads(zlib.decompress(open("resources\\library_compressed_string.txt",'rb').read()))
	pass

def get_module_files(fullname):
	""" return the file to load """
	f=fullname.replace(".","/")
	files=[]
	for x in modules.iterkeys():
		if x.rsplit(".",1)[0]==f or f+"/__init__.py"==x or f+"/__init__.pyc"==x:
			files.append(x)
	return files

def pupy_add_package(pkdic):
	""" update the modules dictionary to allow remote imports of new packages """
	import cPickle
	global modules
	modules.update(cPickle.loads(pkdic))

class PupyPackageLoader:
	def __init__(self, fullname, contents, extension, is_pkg, path):
		self.fullname = fullname
		self.contents = contents
		self.extension = extension
		self.is_pkg=is_pkg
		self.path=path
		#self.archive=""

	def load_module(self, fullname):
		imp.acquire_lock()
		try:
			#print "loading module %s"%fullname
			if fullname in sys.modules:
				return sys.modules[fullname]
			mod=None
			c=None
			if self.extension=="py":
				mod = imp.new_module(fullname)
				mod.__name__ = fullname
				mod.__file__ = "<memimport>\\%s" % self.path.replace("/","\\")
				mod.__loader__ = self
				if self.is_pkg:
					mod.__path__ = [mod.__file__.rsplit("\\",1)[0]]
					mod.__package__ = fullname
				else:
					mod.__package__ = fullname.rsplit('.', 1)[0]
				sys.modules[fullname]=mod
				code = compile(self.contents, mod.__file__, "exec")
				exec self.contents in mod.__dict__
			elif self.extension in ["pyc","pyo"]:
				mod = imp.new_module(fullname)
				mod.__name__ = fullname
				mod.__file__ = "<memimport>\\%s" % self.path.replace("/","\\")
				mod.__loader__ = self
				if self.is_pkg:
					mod.__path__ = [mod.__file__.rsplit("\\",1)[0]]
					#mod.__path__ = [mod.__file__]
					mod.__package__ = fullname
				else:
					mod.__package__ = fullname.rsplit('.', 1)[0]
				sys.modules[fullname]=mod
				c=marshal.loads(self.contents[8:])
				exec c in mod.__dict__
			elif self.extension in ("dll","pyd"):
				initname = "init" + fullname.rsplit(".",1)[-1]
				path=fullname.replace(".","/")+"."+self.extension
				#print "Loading %s from memory"%fullname
				#print "init:%s, %s.%s"%(initname,fullname,self.extension)
				mod = _memimporter.import_module(self.contents, initname, fullname, path)
				mod.__name__=fullname
				mod.__file__ = "<memimport>\\%s" % self.path.replace("/","\\")
				mod.__loader__ = self
				mod.__package__ = fullname.rsplit('.',1)[0]
				sys.modules[fullname]=mod
		except Exception as e:
			if fullname in sys.modules:
				del sys.modules[fullname]
			import traceback
			print "PupyPackageLoader: Error while loading package %s (%s) : %s %s"%(fullname, self.extension, str(e), c)
			raise e
		finally:
			imp.release_lock()
		mod = sys.modules[fullname] # reread the module in case it changed itself
		return mod

class PupyPackageFinder:
	def __init__(self, modules):
		self.modules = modules
		self.modules_list=[x.rsplit(".",1)[0] for x in self.modules.iterkeys()]

	def find_module(self, fullname, path=None):
		imp.acquire_lock()
		try:
			if fullname in ("pywintypes", "pythoncom"):
				fullname = fullname + "%d%d" % sys.version_info[:2]
				fullname = fullname.replace(".", "\\") + ".dll"
			#print "find_module(\"%s\",\"%s\")"%(fullname,path)
			files=get_module_files(fullname)
			if not builtin_memimporter:
				files=[f for f in files if not f.lower().endswith((".pyd",".dll"))]
			if not files:
				#print "%s not found in %s"%(fullname,path)
				return None
			selected=None
			for f in files:
				if f.endswith("/__init__.pyc") or f.endswith("/__init__.py"):
					selected=f # we select packages in priority
			if not selected:
				for f in files:
					if f.endswith(".pyd"):
						selected=f # then we select pyd
			if not selected:
				for f in files:
					if f.endswith(".py"):
						selected=f # we select .py before .pyc
			if not selected:
				selected=files[0]

			#print "%s found in %s"%(fullname,selected)
			content=self.modules[selected]
			extension=selected.rsplit(".",1)[1].strip().lower()
			is_pkg=False
			if selected.endswith("/__init__.py") or selected.endswith("/__init__.pyc"):
				is_pkg=True
			#print "--> Loading %s(%s).%s is_package:%s"%(fullname,selected,extension, is_pkg)
			return PupyPackageLoader(fullname, content, extension, is_pkg, selected)
		except Exception as e:
			raise e
		finally:
			imp.release_lock()

def install():
	sys.meta_path.append(PupyPackageFinder(modules))
	sys.path_importer_cache.clear()

