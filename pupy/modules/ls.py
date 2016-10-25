# -*- coding: UTF8 -*-
from pupylib.PupyModule import *

__class_name__="ls"

@config(cat="admin")
class ls(PupyModule):
    """ list system files """
    is_module=False

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="ls", description=self.__doc__)
        self.arg_parser.add_argument('path', type=str, nargs='?', help='path of a specific file')

    def run(self, args):
        self.client.load_package("pupyutils.basic_cmds")
        self.client.load_package("scandir")
        info, r = self.client.conn.modules["pupyutils.basic_cmds"].ls(args.path)
        if r:
            self.success(info)
            self.log(r)

