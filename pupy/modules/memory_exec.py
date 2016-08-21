# -*- coding: utf-8 -*-
# --------------------------------------------------------------
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE
# --------------------------------------------------------------
from pupylib.PupyModule import *
from pupylib.PupyCompleter import *
from pupylib.utils.pe import get_pe_arch
from pupylib.PupyErrors import PupyModuleError
from pupylib.utils.rpyc_utils import redirected_stdio
from modules.lib.windows.memory_exec import exec_pe
import time

__class_name__="MemoryExec"

@config(compatibilities=["windows"], category="manage")
class MemoryExec(PupyModule):
    """
        Execute a PE executable from memory
        The default behavior is to accept arguments and print stdout of the program once it exits or after timeout seconds
    """
    interactive=1
    def __init__(self, *args, **kwargs):
        PupyModule.__init__(self,*args, **kwargs)
        self.interrupted=False
        self.mp=None
    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="memory_exec", description=self.__doc__)
        #self.arg_parser.add_argument('-p', '--process', default='cmd.exe', help='process to start suspended')
        self.arg_parser.add_argument('--fork', action='store_true', help='fork and do not wait for the child program. stdout will not be retrieved')
        self.arg_parser.add_argument('-i', '--interactive', action='store_true', help='interact with the process stdin.')
        self.arg_parser.add_argument('-m', '--impersonate', action='store_true', help='use the current impersonated token (to use with impersonate module)')
        self.arg_parser.add_argument('-s', '--suspended-process', default="cmd.exe", help='change the suspended process to spawn (default: cmd.exe)')
        self.arg_parser.add_argument('--timeout', metavar='<timeout>', type=float, help='kill the program after <timeout> seconds if it didn\'t exit on its own')
        self.arg_parser.add_argument('-log', help='Save log to file (when process is not interactive)')
        self.arg_parser.add_argument('path', help='path to the exe', completer=path_completer)
        self.arg_parser.add_argument('args', nargs=argparse.REMAINDER, help='optional arguments to pass to the exe')

    def interrupt(self):
        self.info("interrupting remote process, please wait ...")
        if self.mp:
            self.mp.close()
            res=self.mp.get_stdout()
            self.log(res)



    def run(self, args):
        log = exec_pe(self, args.args, path=args.path, interactive=args.interactive, fork=args.fork, timeout=args.timeout, use_impersonation=args.impersonate, suspended_process=args.suspended_process)
        if args.log:
            with open(args.log, 'wb') as output:
                output.write(log)
