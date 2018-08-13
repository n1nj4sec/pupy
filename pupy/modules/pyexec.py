# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

from pupylib.PupyModule import (
    config, PupyModule, PupyArgumentParser,
    REQUIRE_STREAM
)

from pupylib.PupyErrors import PupyModuleError
from pupylib.PupyCompleter import path_completer
from pupylib.utils.rpyc_utils import redirected_stdio

__class_name__="PythonExec"

@config(cat="admin")
class PythonExec(PupyModule):
    """ execute python code on a remote system """

    io = REQUIRE_STREAM

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog='pyexec', description=cls.__doc__)
        cls.arg_parser.add_argument('--file', metavar="<path>", completer=path_completer, help="execute code from .py file")
        cls.arg_parser.add_argument('-R', '--no-redirected-stdio', action='store_true', default=False, help="Do not redirect stdio (no output)")
        cls.arg_parser.add_argument('-c','--code', metavar='<code string>', help="execute python oneliner code. ex : 'import platform;print platform.uname()'")

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

        if args.no_redirected_stdio:
            self.client.conn.execute(code+"\n")
        else:
            with redirected_stdio(self):
                self.client.conn.execute(code+"\n")
