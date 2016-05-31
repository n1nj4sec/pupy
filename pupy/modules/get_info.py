# -*- coding: UTF8 -*-
from pupylib.PupyModule import *

__class_name__="GetInfo"

@config(cat="gather")
class GetInfo(PupyModule):
	""" get some informations about one or multiple clients """
	def init_argparse(self):
		self.arg_parser = PupyArgumentParser(prog='get_info', description=self.__doc__)
		#self.arg_parser.add_argument('arguments', nargs='+', metavar='<command>')
	def run(self, args):
		infos=""
		for k in ["hostname", "user", "release", "version", "os_arch", "pid", "exec_path", "proc_arch", "address", "macaddr", "transport", "launcher", "launcher_args"]:
			infos+="{:<10}: {}\n".format(k,self.client.desc[k])
		self.rawlog(infos)

