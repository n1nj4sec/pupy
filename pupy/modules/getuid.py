# -*- coding: utf-8 -*-
from pupylib.PupyModule import *

__class_name__="getuid"

@config(cat="admin")
class getuid(PupyModule):
    """ get username """
    is_module=False
    dependencies = [ 'pupyutils.basic_cmds' ]

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="getuid", description=self.__doc__)

    def run(self, args):
        self.success(self.client.conn.modules["pupyutils.basic_cmds"].getuid())
