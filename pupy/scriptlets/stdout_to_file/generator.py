#!/usr/bin/env python
# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
import textwrap, random, string
from scriptlets import *

class ScriptletGenerator(Scriptlet):
    """ redirect stdout to a file to debug windows payloads """

    dependencies=[]
    arguments={
        'path': 'path to debug file. default %TEMP%\\pupy.log'
    }

    def __init__(self, path="%TEMP%\\pupy.log"):
        self.path=path

    def generate(self):
        return textwrap.dedent("""
        import sys, os.path
        class RedirToFile(object):
            def __init__(self, path):
                self.path=path
            softspace = 0
            def read(self):
                pass
            def write(self, text):
                with open(self.path, 'a') as f:
                    f.write(text)
            def flush(self):
                pass
        path=os.path.join(os.path.expandvars({}))
        sys.stdout = RedirToFile(path)
        sys.stderr = RedirToFile(path)

        """.format(repr(self.path)))


