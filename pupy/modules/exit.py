# -*- coding: UTF8 -*-
from pupylib.PupyModule import *
from pupylib.PupyErrors import PupyModuleError

__class_name__="ExitModule"

class ExitModule(PupyModule):
    """ exit the client on the other side """
    is_module=False
    
    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="exit", description=self.__doc__)
        self.arg_parser.add_argument('--yes', action="store_true", help='exit confirmation')

    def run(self, args):
        if args.yes:
            try:
                self.client.conn.exit()
            except Exception:
                pass
        else:
            raise PupyModuleError("Warning: if you do this you will loose your shell. Please conform with --yes to perform this action.")
        return "client exited"

