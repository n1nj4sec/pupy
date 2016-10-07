# -*- coding: UTF8 -*-
from pupylib.PupyModule import *
from pupylib.utils.rpyc_utils import redirected_stdio

__class_name__="mv"

@config(cat="admin")
class mv(PupyModule):
	""" move file or directory """

	def init_argparse(self):
		self.arg_parser = PupyArgumentParser(prog="mv", description=self.__doc__)		
		self.arg_parser.add_argument('src', type=str, action='store')
		self.arg_parser.add_argument('dst', type=str, action='store')

	def run(self, args):
		self.client.load_package("pupyutils.basic_cmds")
		with redirected_stdio(self.client.conn):
		    self.client.conn.modules["pupyutils.basic_cmds"].mv(args.src, args.dst)
