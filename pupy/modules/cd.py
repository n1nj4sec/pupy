# -*- coding: UTF8 -*-
from pupylib.PupyModule import *
from pupylib.utils.rpyc_utils import redirected_stdio

__class_name__="cd"

@config(cat="admin")
class cd(PupyModule):
    """ change directory """

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="cd", description=self.__doc__)
        self.arg_parser.add_argument('path', type=str, nargs='?', help='path of a specific directory')

    def run(self, args):
        self.client.load_package("pupyutils.basic_cmds")
        with redirected_stdio(self.client.conn):
            self.client.conn.modules["pupyutils.basic_cmds"].cd(args.path)
