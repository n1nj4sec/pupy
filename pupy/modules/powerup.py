# -*- coding: UTF8 -*-
from pupylib.PupyModule import *
import os
from modules.lib.windows.powershell_upload import execute_powershell_script

__class_name__="PowerUp"
ROOT=os.path.abspath(os.path.join(os.path.dirname(__file__),".."))

@config(compat="windows", category="admin")
class PowerUp(PupyModule):
    """ trying common Windows privilege escalation methods"""
    
    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="PowerUp", description=self.__doc__)

    def run(self, args):
        content = open(os.path.join(ROOT, "external", "PowerSploit", "Privesc", "PowerUp.ps1"), 'r').read()

        # launch all PowerUp checks
        function = 'Invoke-AllChecks'

        output = execute_powershell_script(self, content, function)
        
        # parse output depending on the PowerUp output
        output = output.replace('\r\n\r\n\r\n', '\r\n\r\n').replace("\n\n", "\n").replace("\n\n", "\n")
        self.success("%s" % output)