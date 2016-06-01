#!/usr/bin/env python
# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

import threading

def threaded(fct):
    def new(*args, **kwargs):
        t=threading.Thread(target=fct, args=args, kwargs=kwargs)
        t.daemon=True
        t.start()
        return t
    return new
