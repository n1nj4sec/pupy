# -*- coding: UTF8 -*-
from pupylib.PupyModule import *
# import ctypes
from pupylib.utils.rpyc_utils import redirected_stdio

__class_name__="Drives"

@config(compat="windows", category="admin")
class Drives(PupyModule):
	""" List valid drives in the system """
	
	dependencies=["win32api","win32com","pythoncom","winerror"]
	
	def init_argparse(self):
		self.arg_parser = PupyArgumentParser(prog="drives", description=self.__doc__)

	def run(self, args):
		self.client.load_package("wmi")
		self.client.load_package("pupwinutils.drives")
		
		with redirected_stdio(self.client.conn):
			self.client.conn.modules['pupwinutils.drives'].list_drives()