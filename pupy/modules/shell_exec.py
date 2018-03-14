# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
from pupylib.PupyModule import *
import subprocess
from rpyc.utils.helpers import restricted
from modules.lib.utils.shell_exec import shell_exec
__class_name__="ShellExec"

@config(cat="admin")
class ShellExec(PupyModule):
    """ execute shell commands on a remote system """

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog='shell_exec', description=cls.__doc__)
        cls.arg_parser.add_argument('-s', '--shell', help="default to /bin/sh on linux or cmd.exe on windows")
        cls.arg_parser.add_argument('argument', help='use unix like syntax and put simple quotes if there is multiple arguments')
        cls.arg_parser.add_argument('-H', '--hide', action='store_true', help='launch process on background (only for windows)')
        cls.arg_parser.add_argument('-c', '--codepage', default=None, help='decode using codepage')

    def run(self, args):
        if not args.hide:
            self.log(shell_exec(self.client, args.argument, shell=args.shell, encoding=args.codepage))
        elif args.hide and self.client.is_windows():
            try:
                self.client.load_package("pupwinutils.processes")
                p=self.client.conn.modules['pupwinutils.processes'].start_hidden_process(args.argument)
                pid=p.pid
                self.success("Process created with pid %s" % p.pid)
            except Exception, e:
                self.error("Error creating the process: %s" % e)
        else:
            self.error('--hide option works only for Windows hosts')
