# -*- coding: UTF8 -*-
from pupylib.PupyModule import *

__class_name__="mv"

@config(cat="admin")
class mv(PupyModule):
    """ move file or directory """
    is_module=False

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="mv", description=self.__doc__)        
        self.arg_parser.add_argument('src', type=str, action='store')
        self.arg_parser.add_argument('dst', type=str, action='store')

    def run(self, args):
        self.client.load_package("pupyutils.basic_cmds")
        r=self.client.conn.modules["pupyutils.basic_cmds"].mv(args.src, args.dst)
        if r:
            self.log(r)
