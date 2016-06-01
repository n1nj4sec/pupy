#!/usr/bin/env python
# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
import signal

winch_handler=None

def set_signal_winch(handler):
    """ return the old signal handler """
    global winch_handler
    old_handler=winch_handler
    winch_handler=handler
    return old_handler

def signal_winch(signum, frame):
    global winch_handler
    if winch_handler:
        return winch_handler(signum, frame)

signal.signal(signal.SIGWINCH, signal_winch)

