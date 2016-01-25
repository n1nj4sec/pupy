# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
from pupylib.PupyModule import *
import subprocess
from rpyc.utils.helpers import restricted
from modules.lib.utils.shell_exec import shell_exec
__class_name__="ShellExec"

@category("exploit")
class ShellExec(PupyModule):
	""" execute shell commands on a remote system """
	def init_argparse(self):
		self.arg_parser = PupyArgumentParser(prog='shell_exec', description=self.__doc__)
		self.arg_parser.add_argument('-s', '--shell', help="default to /bin/sh on linux or cmd.exe on windows")
		self.arg_parser.add_argument('argument')
	def run(self, args):
		self.log(shell_exec(self.client, args.argument, shell=args.shell))
