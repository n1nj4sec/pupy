# -*- coding: utf-8 -*-
from pupylib.PupyModule import *

__class_name__="cp"

@config(cat="admin")
class cp(PupyModule):
    """ copy file or directory """
    is_module=False

    dependencies = [ 'pupyutils.basic_cmds' ]

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="cp", description=self.__doc__)
        self.arg_parser.add_argument('src', type=str, action='store')
        self.arg_parser.add_argument('dst', type=str, action='store')

    def run(self, args):
        r = self.client.conn.modules["pupyutils.basic_cmds"].cp(args.src, args.dst)
        if r:
            self.log(r)
