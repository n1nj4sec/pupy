# -*- coding: UTF8 -*-
from pupylib.PupyModule import *

__class_name__="KillModule"

@config(cat="general")
class KillModule(PupyModule):
    """ kill a process """

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="kill", description=self.__doc__)
        self.arg_parser.add_argument('pid', type=int, help='pid to kill')

    def run(self, args):
        self.client.conn.modules.os.kill(args.pid,9)
        self.success("process killed !")

