#!/usr/bin/env python
# -*- coding: utf-8 -*-
import StringIO, zipfile, os.path, imp, sys
import marshal
import zlib

def get_encoded_library_string():
	filepath=None
	filepath=os.path.join("resources","library.zip")

	f = StringIO.StringIO()
	f.write(open(filepath, "rb").read())

	zip = zipfile.ZipFile(f)

	modules = dict([
		(z.filename, zip.open(z.filename,).read()) for z in zip.infolist() \
		if os.path.splitext(z.filename)[1] in [
			'.py', '.pyd', '.dll', '.pyc', '.pyo', '.so'
		]
	])

	return zlib.compress(marshal.dumps(modules),9)

with open(os.path.join("resources","library_compressed_string.txt"),'wb') as w:
	w.write(get_encoded_library_string())
