# -*- coding: UTF8 -*-
from pupylib.PupyModule import *
import os
from modules.lib.windows.powershell_upload import execute_powershell_script

__class_name__="CheckVM"
ROOT=os.path.abspath(os.path.join(os.path.dirname(__file__),".."))

@config(compat="windows", category="gather")
class CheckVM(PupyModule):
    """ check if running on Virtual Machine """
    
    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="CheckVM", description=self.__doc__)

    def run(self, args):
        content = open(os.path.join(ROOT, "external", "Nishang", "Check-VM.ps1"), 'r').read()
        function = 'Check-VM'
        output = execute_powershell_script(self, content, function)
        if output.strip():
            self.success("%s" % output)
        else:
            self.success("No virtual machine detected")
