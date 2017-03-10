# -*- coding: UTF8 -*-
from pupylib.PupyModule import *

__class_name__="cd"

@config(cat="admin")
class cd(PupyModule):
    """ change directory """
    is_module=False

    dependencies = ['pupyutils.basic_cmds']

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="cd", description=self.__doc__)
        self.arg_parser.add_argument('path', type=str, nargs='?', help='path of a specific directory')

    def run(self, args):
        r = self.client.conn.modules["pupyutils.basic_cmds"].cd(args.path)
        if r:
            self.log(r)
