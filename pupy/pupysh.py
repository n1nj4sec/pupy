#!/usr/bin/env python
# -*- coding: UTF8 -*-

# --------------------------------------------------------------
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
# --------------------------------------------------------------

import pupylib.PupyServer
import pupylib.PupyCmd
import logging
import time
import traceback
import argparse
import os
import os.path

__author__='Nicolas VERDIER'
__version__='v1.0.0'

def print_version():
	print("Pupy - %s"%(__version__))

if __name__=="__main__":
	if os.path.dirname(__file__):
		os.chdir(os.path.dirname(__file__))
	parser = argparse.ArgumentParser(prog='ptrconsole', description="Pupy console")
	parser.add_argument('-d', '--debug', help="print DEBUG level logs", action="store_const", dest="loglevel", const=logging.DEBUG, default=logging.WARNING)
	parser.add_argument('-v', '--verbose', help="print INFO level logs", action="store_const", dest="loglevel", const=logging.INFO)
	parser.add_argument('--version', help="print version and exit", action='store_true')
	args=parser.parse_args()
	if args.version:
		print_version()
		exit(0)
	if args.loglevel==logging.INFO:
		print("logging level: INFO")
	elif args.loglevel==logging.DEBUG:
		print("logging level: DEBUG")
	logging.basicConfig(format='%(asctime)-15s - %(levelname)-5s - %(message)s')
	logging.getLogger().setLevel(args.loglevel)

	pupyServer=pupylib.PupyServer.PupyServer()
	try:
		import __builtin__ as builtins
	except ImportError:
		import builtins
	builtins.glob_pupyServer=pupyServer # dirty ninja trick for this particular case avoiding to touch rpyc source code
	pupyServer.start()
	pcmd=pupylib.PupyCmd.PupyCmd(pupyServer)
	while True:
		try:
			pcmd.cmdloop()
		except Exception as e:
			print(traceback.format_exc())
			pcmd.intro=''

	
