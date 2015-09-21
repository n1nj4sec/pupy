#!/usr/bin/env python
# -*- coding: UTF8 -*-
import StringIO, zipfile, os.path, imp, sys
import marshal
import zlib

def get_encoded_library_string(arch):
	filepath=None
	if arch=="x86":
		filepath=os.path.join("resources","libraryx86.zip")
	elif arch=="x64":
		filepath=os.path.join("resources","libraryx64.zip")
	else:
		raise Exception("unknown arch %s"%arch)
	f = StringIO.StringIO()
	f.write(open(filepath, "rb").read())

	zip = zipfile.ZipFile(f)

	modules = dict([(z.filename, zip.open(z.filename,).read()) for z in zip. infolist() if os.path.splitext(z.filename)[1] in [".py",".pyd",".dll",".pyc",".pyo"]])

	return zlib.compress(marshal.dumps(modules),9)
try:
	with open(os.path.join("resources","library_compressed_string_x86.txt"),'wb') as w:
		w.write(get_encoded_library_string("x86"))
	print "x86 encoded library generated"
except Exception as e:
	print str(e)
try:
	with open(os.path.join("resources","library_compressed_string_x64.txt"),'wb') as w:
		w.write(get_encoded_library_string("x64"))
	print "x64 encoded library generated"
except Exception as e:
	print str(e)
