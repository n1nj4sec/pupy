# -*- coding: UTF8 -*-
from pupylib.PupyModule import *

__class_name__="GetPrivsModule"

@compatibility("windows")
@category("privesc")
class GetPrivsModule(PupyModule):
	""" try to get SeDebugPrivilege for the current process """
	dependencies=["psutil"]
	def init_argparse(self):
		self.arg_parser = PupyArgumentParser(prog="getprivs", description=self.__doc__)

	def run(self, args):
		#self.client.conn.modules.ctypes.windll.user32.MessageBoxA(None, args.text, args.title, 0)
		self.client.load_package("pupwinutils.getsystem")
		self.client.conn.modules["pupwinutils.getsystem"].EnablePrivilege("SeDebugPrivilege")
		self.success("SeDebugPrivilege enabled !")

