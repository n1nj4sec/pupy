#!/usr/bin/env python
# -*- coding: UTF8 -*-
import sys
import binascii

MAX_CHAR_PER_LINE=50

if __name__=="__main__":
	h_file=""
	file_bytes=b""
	with open(sys.argv[1], "rb") as f:
		file_bytes=f.read()
	h_file += "int %s_size = %s;"%(sys.argv[1].replace(".","_").replace("\\","_").replace("/","_"), len(file_bytes))
	h_file += "\nchar %s_start[] = {\n"%sys.argv[1].replace(".","_").replace("\\","_").replace("/","_")
	current_size=0

	for c in file_bytes:
		h_file+="'\\x%s',"%binascii.hexlify(c)
		current_size+=1
		if current_size>MAX_CHAR_PER_LINE:
			current_size=0
			h_file+="\n"
		
	h_file += "'\\x00' };\n"

	with open(sys.argv[1].replace(".","_").replace("\\","_").replace("/","_")+".c",'w') as w:
		w.write(h_file)
		
	
