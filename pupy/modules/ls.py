# -*- coding: utf-8 -*-
from pupylib.PupyModule import *

__class_name__="ls"

@config(cat="admin")
class ls(PupyModule):
    """ list system files """
    is_module=False

    dependencies = [ 'pupyutils.basic_cmds', 'scandir' ]

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="ls", description=self.__doc__)
        self.arg_parser.add_argument('path', type=str, nargs='?', help='path of a specific file')

    def run(self, args):
        info, r = self.client.conn.modules["pupyutils.basic_cmds"].ls(args.path)
        if r:
            self.success(info)
            self.log(r)
