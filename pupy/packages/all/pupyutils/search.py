#!/usr/bin/env python
# -*- coding: UTF8 -*-
import os
import os.path
import re

def search_file(path, search_strings):
	buf=b""
	line_nb=0
	try:
		with open(path, 'rb') as f:
			for line in f:
				line=line.lower()
				for s in search_strings:
					start=0
					while True:
						i=line.find(s.lower(), start)
						if i==-1:
							break
						start=i+1
						yield (line_nb, line[i-50:i+50].strip())
				line_nb+=1
	except Exception:
		pass


def search_path(path, search_strings, files_extensions=None, max_size=None):
	""" search recursively for a string in all files in the path """
	if not files_extensions:
		files_extensions=None
	if files_extensions is not None:
		files_extensions=tuple(files_extensions)
	for root, dirs, files in os.walk(path):
		for f in files:
			if files_extensions is None or f.lower().endswith(files_extensions):
				if max_size is None or os.path.getsize(os.path.join(root,f))<max_size:
					for res in search_file(os.path.join(root,f),search_strings):
						yield (os.path.join(root,f), res[0], res[1])
	
if __name__=="__main__":
	import sys
	search_path(sys.argv[1],[sys.argv[2]])
