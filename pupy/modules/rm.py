# -*- coding: UTF8 -*-
from pupylib.PupyModule import *
from pupylib.utils.rpyc_utils import redirected_stdio

__class_name__="rm"

@config(cat="admin")
class rm(PupyModule):
	""" remove a file or a directory """

	def init_argparse(self):
		self.arg_parser = PupyArgumentParser(prog="rm", description=self.__doc__)		
		self.arg_parser.add_argument('path', type=str, action='store')

	def run(self, args):
		self.client.load_package("pupyutils.basic_cmds")
		with redirected_stdio(self.client.conn):
		    self.client.conn.modules["pupyutils.basic_cmds"].rm(args.path)
