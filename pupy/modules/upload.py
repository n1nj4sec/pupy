# -*- coding: UTF8 -*-
from pupylib.PupyModule import *
from pupylib.PupyCompleter import *
from rpyc.utils.classic import upload
import os
import os.path

__class_name__="UploaderScript"

class UploaderScript(PupyModule):
	""" upload a file/directory to a remote system """
	def init_argparse(self):
		self.arg_parser = PupyArgumentParser(prog='download', description=self.__doc__)
		self.arg_parser.add_argument('local_file', metavar='<local_path>', completer=path_completer)
		self.arg_parser.add_argument('remote_file', metavar='<remote_path>')
	def run(self, args):
		upload(self.client.conn, args.local_file, args.remote_file)
		self.success("file local:%s uploaded to remote:%s"%(args.local_file, args.remote_file))

