# -*- coding: UTF8 -*-
from pupylib.PupyModule import *

__class_name__="cat"

@config(cat="admin")
class cat(PupyModule):
    """ show contents of a file """
    is_module=False

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="cat", description=self.__doc__)        
        self.arg_parser.add_argument('path', type=str, action='store')

    def run(self, args):
        self.client.load_package("pupyutils.basic_cmds")
        r=self.client.conn.modules["pupyutils.basic_cmds"].cat(args.path)
        if r:
            self.log(r)
