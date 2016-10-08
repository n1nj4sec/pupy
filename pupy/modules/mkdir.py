# -*- coding: UTF8 -*-
from pupylib.PupyModule import *

__class_name__="mkdir"

@config(cat="admin")
class mkdir(PupyModule):
    """ create an empty directory """
    is_module=False
    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="mkdir", description=self.__doc__)
        self.arg_parser.add_argument('dir', type=str, help='directory name')

    def run(self, args):
        self.client.load_package("pupyutils.basic_cmds")
        r=self.client.conn.modules["pupyutils.basic_cmds"].mkdir(args.dir)
        if r:
            self.log(r)

