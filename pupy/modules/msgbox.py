# -*- coding: UTF8 -*-
from pupylib.PupyModule import *

__class_name__="MsgBoxPopup"

class MsgBoxPopup(PupyModule):
	""" Pop up a custom message box """

	def init_argparse(self):
		self.arg_parser = PupyArgumentParser(prog="msgbox", description=self.__doc__)
		self.arg_parser.add_argument('--title', help='msgbox title')
		self.arg_parser.add_argument('text', help='text to print in the msgbox :)')

	@windows_only
	def is_compatible(self):
		pass

	def run(self, args):
		#self.client.conn.modules.ctypes.windll.user32.MessageBoxA(None, args.text, args.title, 0)
		self.client.load_package("pupwinutils.msgbox")
		self.client.conn.modules['pupwinutils.msgbox'].MessageBox(args.text, args.title)
		self.log("message box popped !")

