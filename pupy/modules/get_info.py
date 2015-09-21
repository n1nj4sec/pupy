# -*- coding: UTF8 -*-
from pupylib.PupyModule import *

__class_name__="GetInfo"

class GetInfo(PupyModule):
	""" get some informations about one or multiple clients """
	def init_argparse(self):
		self.arg_parser = PupyArgumentParser(prog='get_info', description=self.__doc__)
		#self.arg_parser.add_argument('arguments', nargs='+', metavar='<command>')
	def run(self, args):
		infos=""
		for k,v in self.client.desc.iteritems():
			if k not in ["conn","id","user","platform"]:
				infos+="{:<10}: {}\n".format(k,v)
		self.rawlog(infos)

