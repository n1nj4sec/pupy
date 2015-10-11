# -*- coding: UTF8 -*-
from pupylib.PupyModule import *
from pupylib.utils.rpyc_utils import obtain

__class_name__="PsModule"

class PsModule(PupyModule):
	""" list processes """

	def init_argparse(self):
		self.arg_parser = PupyArgumentParser(prog="ps", description=self.__doc__)
		self.arg_parser.add_argument('--all', '-a', action='store_true', help='more info')

	@windows_only
	def is_compatible(self):
		pass

	def run(self, args):
		#self.client.conn.modules.ctypes.windll.user32.MessageBoxA(None, args.text, args.title, 0)
		self.client.load_package("psutil")
		self.client.load_package("pupwinutils.processes")
		outputlist=self.client.conn.modules["pupwinutils.processes"].enum_processes()
		outputlist=obtain(outputlist) #pickle the list of proxy objects with obtain is really faster
		columns=['username', 'pid', 'arch', 'exe']
		if args.all:
			columns=['username', 'pid', 'arch', 'name', 'exe', 'cmdline', 'status']
			for dic in outputlist:
				dic["cmdline"]=' '.join(dic['cmdline'][1:])
		else:
			for dic in outputlist:
				if 'exe' in dic and not dic['exe'] and 'name' in dic and dic['name']:
					dic['exe']=dic['name']
				if 'username' in dic and dic['username'] is None:
					dic['username']=""
		self.rawlog(self.formatter.table_format(outputlist, wl=columns))

