# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

from pupylib.PupyModule import (
    config, PupyModule, PupyArgumentParser,
    REQUIRE_REPL
)

from pupylib.utils.rpyc_utils import redirected_stdo
import readline


__class_name__="InteractivePythonShell"


def enqueue_output(out, queue):
    for c in iter(lambda: out.read(1), b""):
        queue.put(c)

@config(cat="admin")
class InteractivePythonShell(PupyModule):
    """ open an interactive python shell on the remote client """

    io = REQUIRE_REPL
    dependencies = ['pyshell']

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog='pyshell', description=cls.__doc__)

    def run(self, args):
        PyShellController = self.client.remote('pyshell.controller', 'PyShellController', False)

        try:
            with redirected_stdo(self):
                old_completer=readline.get_completer()
                try:
                    psc = PyShellController()
                    readline.set_completer(psc.get_completer())
                    readline.parse_and_bind('tab: complete')

                    while True:
                        cmd=raw_input(">>> ")
                        psc.write(cmd)

                finally:
                    readline.set_completer(old_completer)
                    readline.parse_and_bind('tab: complete')

        except (EOFError, KeyboardInterrupt):
            self.log('pyshell closed')
