# -*- coding: UTF8 -*-
from pupylib.PupyModule import *

__class_name__="GetPrivsModule"

@config(compat=["windows"], cat="manage")
class GetPrivsModule(PupyModule):
    """ try to get SeDebugPrivilege for the current process """
    dependencies=["psutil", "pupwinutils.security"]
    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="getprivs", description=self.__doc__)

    def run(self, args):
        self.client.conn.modules["pupwinutils.security"].EnablePrivilege("SeDebugPrivilege")
        self.success("SeDebugPrivilege enabled !")

