#!/usr/bin/env python
# -*- coding: utf-8 -*-
import StringIO, zipfile, os.path, imp, sys, os
import marshal
#import pylzma
import struct

def get_encoded_library_string(filepath):
	dest = os.path.dirname(filepath)
	if not os.path.exists(dest):
		os.makedirs(dest)

	f = StringIO.StringIO()
	f.write(open(filepath, 'rb').read())

	zip = zipfile.ZipFile(f)

	modules = dict([
		(z.filename, zip.open(z.filename,).read()) for z in zip.infolist() \
		if os.path.splitext(z.filename)[1] in [
			'.py', '.pyd', '.dll', '.pyc', '.pyo', '.so', '.toc'
		]
	])

	return marshal.dumps(modules)

with open(sys.argv[1],'wb') as w:
	w.write(get_encoded_library_string(sys.argv[2]))
