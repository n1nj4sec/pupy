#!/usr/bin/env python
# -*- coding: UTF8 -*-
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

