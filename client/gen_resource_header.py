#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import binascii
import pylzma
import struct

MAX_CHAR_PER_LINE=50

if __name__=="__main__":
	h_file=""
	file_bytes=b""
	with open(sys.argv[1], "rb") as f:
		file_bytes=f.read()

	attribute = '\n'.join([
		'__attribute__(({}))'.format(x) for x in sys.argv[2:]
	])

	payload_len = len(file_bytes)
	payload = struct.pack('>I', payload_len) + pylzma.compress(
		file_bytes,dictionary=24,fastBytes=255)

	h_file += "static const int %s_size = %s;"%(sys.argv[1].replace(".","_").replace("\\","_").replace("/","_"), len(payload))
	h_file += attribute
	h_file += "\nstatic const char %s_start[] = {\n"%sys.argv[1].replace(".","_").replace("\\","_").replace("/","_")
	current_size=0

	for c in payload:
		h_file+="'\\x%s',"%binascii.hexlify(c)
		current_size+=1
		if current_size>MAX_CHAR_PER_LINE:
			current_size=0
			h_file+="\n"

	h_file += "'\\x00' };\n"

	with open(sys.argv[1].replace(".","_").replace("\\","_").replace("/","_")+".c",'w') as w:
		w.write(h_file)
