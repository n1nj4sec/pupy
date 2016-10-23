# -*- coding: UTF8 -*-
from pupylib.PupyModule import *

__class_name__="getuid"

@config(cat="admin")
class getuid(PupyModule):
    """ get username """
    is_module=False

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="getuid", description=self.__doc__)

    def run(self, args):
        self.client.load_package("pupyutils.basic_cmds")
        self.success(self.client.conn.modules["pupyutils.basic_cmds"].getuid())

