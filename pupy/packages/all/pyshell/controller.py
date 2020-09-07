# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file
# at the root of the project for the detailed licence terms

from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import code

from . import PythonCompleter


def new_exit(*args, **kwargs):
    print("use ctrl+D to exit the interactive python interpreter.")


class PyShellController(object):
    __slots__ = (
        '_local_ns', 'console', 'completer'
    )

    def __init__(self):
        self._local_ns = {
            'exit': new_exit
        }

        self.console = code.InteractiveConsole(self._local_ns)
        self.completer = PythonCompleter.PythonCompleter(
            global_ns=globals(), local_ns=self._local_ns
        ).complete

    def write(self, line):
        self.console.push(line)

    def get_completer(self):
        return self.completer
