#!/usr/bin/env python
# -*- coding: UTF8 -*-

LOAD_PACKAGE=1
LOAD_DLL=2
EXEC=3

# dependencies to load for each modules
packages_dependencies={

	"pupwinutils.memexec" : [
		(LOAD_PACKAGE, "pupymemexec"),
	],

}
