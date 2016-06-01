# -*- coding: UTF8 -*-
from pupylib.PupyModule import *

__class_name__="PupyMod"

@config(compat="windows", cat="manage", tags=["lock", "screen", "session"])
class PupyMod(PupyModule):
    """ Lock the session """

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="lock_screen", description=self.__doc__)

    def run(self, args):
        if self.client.conn.modules['ctypes'].windll.user32.LockWorkStation():
            self.success("windows locked")
        else:
            self.error("couldn't lock the screen")

