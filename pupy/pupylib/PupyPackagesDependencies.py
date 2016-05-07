#!/usr/bin/env python
# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

LOAD_PACKAGE=1
LOAD_DLL=2
EXEC=3

# dependencies to load for each modules
packages_dependencies={

	"pupwinutils.memexec" : [
		(LOAD_PACKAGE, "pupymemexec"),
	],
	"memorpy" : [
		(LOAD_PACKAGE, "win32api"),
		(LOAD_PACKAGE, "win32console"),
		(LOAD_PACKAGE, "win32gui"),
		(LOAD_PACKAGE, "win32security"),
		(LOAD_PACKAGE, "win32con"),
	],

}
