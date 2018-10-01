#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
import textwrap
from scriptlets import Scriptlet

class ScriptletGenerator(Scriptlet):
    """ change pupy process's name """

    dependencies = {
        'linux': ['hide_process']
    }

    arguments = {
        'name': 'ex: compiz'
    }

    def __init__(self, name="compiz"):
        self.name=name

    def generate(self, os):
        return textwrap.dedent("""
        import sys
        if sys.platform=="linux2":
            import hide_process
            hide_process.change_argv(argv={})
        """.format(repr(self.name)))
