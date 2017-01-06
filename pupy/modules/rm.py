# -*- coding: utf-8 -*-
from pupylib.PupyModule import *

__class_name__="rm"

@config(cat="admin")
class rm(PupyModule):
    """ remove a file or a directory """
    is_module = False
    dependencies = ['pupyutils.basic_cmds']

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="rm", description=self.__doc__)
        self.arg_parser.add_argument('path', type=str, action='store')

    def run(self, args):
        r = self.client.conn.modules["pupyutils.basic_cmds"].rm(args.path)
        if r:
            self.log(r)
