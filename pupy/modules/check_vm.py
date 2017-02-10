# -*- coding: UTF8 -*-
from pupylib.PupyModule import *
import os
from modules.lib.windows.powershell_upload import execute_powershell_script

__class_name__="CheckVM"
ROOT=os.path.abspath(os.path.join(os.path.dirname(__file__),".."))

@config(category="gather")
class CheckVM(PupyModule):
    """ check if running on Virtual Machine """
    
    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="CheckVM", description=self.__doc__)

    def run(self, args):
        if self.client.is_windows():
            content = open(os.path.join(ROOT, "external", "Nishang", "Check-VM.ps1"), 'r').read()
            function = 'Check-VM'
            output = execute_powershell_script(self, content, function)
            if output.strip():
                self.success("%s" % output)
            else:
                self.success("No virtual machine detected")
        elif self.client.is_linux():
            self.client.load_package("checkvm")
            vm = self.client.conn.modules["checkvm"].checkvm()
            if vm:
                self.success('This appears to be a %s virtual machine' % vm)
            else:
                self.success('This does not appear to be a virtual machine')
        elif self.client.is_darwin():
            self.client.load_package("checkvm")
            self.info('Be patient, could take a while')
            vm = self.client.conn.modules["checkvm"].checkvm()
            if vm:
                self.success('This appears to be a %s virtual machine' % vm)
            else:
                self.success('This does not appear to be a virtual machine')

