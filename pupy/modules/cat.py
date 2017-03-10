# -*- coding: utf-8 -*-
from pupylib.PupyModule import *

__class_name__="cat"

@config(cat="admin")
class cat(PupyModule):
    """ show contents of a file """
    is_module=False
    dependencies = [ 'pupyutils.basic_cmds' ]

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="cat", description=self.__doc__)
        self.arg_parser.add_argument('path', type=str, action='store')

    def run(self, args):
        r = self.client.conn.modules["pupyutils.basic_cmds"].cat(args.path)
        if r:
            self.log(r)
