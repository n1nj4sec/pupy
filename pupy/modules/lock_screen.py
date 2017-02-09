# -*- coding: UTF8 -*-
from pupylib.PupyModule import *
import subprocess

__class_name__="PupyMod"

@config(compat=["windows", "darwin"], cat="manage", tags=["lock", "screen", "session"])
class PupyMod(PupyModule):
    """ Lock the session """

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="lock_screen", description=self.__doc__)

    def run(self, args):
        ok = False
        if self.client.is_windows():
            ok = self.client.conn.modules['ctypes'].windll.user32.LockWorkStation()
        elif self.client.is_darwin():
            ok = self.client.conn.modules.subprocess.Popen('/System/Library/CoreServices/Menu\ Extras/User.menu/Contents/Resources/CGSession -suspend', stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, shell=True)

        if ok:
            self.success("windows locked")
        else:
            self.error("couldn't lock the screen")
