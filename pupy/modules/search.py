# -*- coding: UTF8 -*-
from pupylib.PupyModule import *

__class_name__="SearchModule"

class SearchModule(PupyModule):
	""" walk through a directory and recursively search a string into files """
	daemon=True
	def init_argparse(self):
		self.arg_parser = PupyArgumentParser(prog="search", description=self.__doc__)
		self.arg_parser.add_argument('path', help='path')
		self.arg_parser.add_argument('-e','--extensions',metavar='ext1,ext2,...', help='limit to some extensions')
		self.arg_parser.add_argument('strings', nargs='+', metavar='string', help='strings to search')
		self.arg_parser.add_argument('-m','--max-size', type=int, default=None, help='max file size')

	def run(self, args):
		self.client.load_package("pupyutils.search", force=True)
		exts=[]
		if args.extensions:
			exts=args.extensions.split(',')
		self.info("searching strings %s in %s ..."%(args.strings, args.path))
		for res in self.client.conn.modules['pupyutils.search'].search_path(args.path, args.strings, files_extensions=exts, max_size=args.max_size):
			self.success("%s:%s > %s"%(res[0],res[1],res[2]))
		self.info("search finished !")

