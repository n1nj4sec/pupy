# -*- coding: UTF8 -*-
from pupylib.PupyModule import *
from pupylib.utils.rpyc_utils import redirected_stdio

__class_name__="InteractiveShell"


class InteractiveShell(PupyModule):
	""" open an interactive command shell """
	max_clients=1
	def init_argparse(self):
		self.arg_parser = PupyArgumentParser(description=self.__doc__)
		#self.arg_parser.add_argument('arguments', nargs='+', metavar='<command>')

	def run(self, args):
		self.client.load_package("interactive_shell")
		program="/bin/sh"
		encoding=None
		if self.client.is_windows():
			program="cmd.exe"
			encoding="cp437"
		with redirected_stdio(self.client.conn):
			self.client.conn.modules.interactive_shell.interactive_open(program=program, encoding=encoding)

