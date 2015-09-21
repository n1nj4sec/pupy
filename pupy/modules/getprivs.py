# -*- coding: UTF8 -*-
from pupylib.PupyModule import *

__class_name__="GetPrivsModule"

class GetPrivsModule(PupyModule):
	""" try to get SeDebugPrivilege for the current process """

	def init_argparse(self):
		self.arg_parser = PupyArgumentParser(prog="getprivs", description=self.__doc__)

	@windows_only
	def is_compatible(self):
		pass

	def run(self, args):
		#self.client.conn.modules.ctypes.windll.user32.MessageBoxA(None, args.text, args.title, 0)
		self.client.load_package("pupwinutils.security", force=True)
		self.client.conn.modules["pupwinutils.security"].EnablePrivilege("SeDebugPrivilege")
		self.success("SeDebugPrivilege enabled !")

