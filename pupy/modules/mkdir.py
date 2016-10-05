# -*- coding: UTF8 -*-
from pupylib.PupyModule import *
from pupylib.utils.rpyc_utils import redirected_stdio

__class_name__="mkdir"

@config(cat="admin")
class mkdir(PupyModule):
    """ create an empty directory """

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="mkdir", description=self.__doc__)
        self.arg_parser.add_argument('dir', type=str, help='directory name')

    def run(self, args):
        self.client.load_package("pupyutils.basic_cmds")
        with redirected_stdio(self.client.conn):
            self.client.conn.modules["pupyutils.basic_cmds"].mkdir(args.dir)

