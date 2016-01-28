#!/usr/bin/env python
# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
import jnius

__all__=["vibrate"]

def vibrate(self, pattern, repeat=None):
	""" take a list of int as pattern """
	PythonActivity = jnius.autoclass('org.renpy.android.PythonService')
	Context = jnius.autoclass('android.content.Context')
	activity = PythonActivity.mService
	vibrator = activity.getSystemService(Context.VIBRATOR_SERVICE)
	if vibrator.hasVibrator():
		try:
			if repeat:
				vibrator.vibrate(pattern, repeat)
			else:
				vibrator.vibrate(pattern)
		except KeyboardInterrupt:
			vibrator.cancel()
			raise
	else:
		raise RuntimeError("The device does not have a vibrator")

